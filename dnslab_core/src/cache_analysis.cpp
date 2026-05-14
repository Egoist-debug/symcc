#include "dnslab_core/cache_analysis.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace dnslab {

namespace {

const std::regex kClassRe("^(?:IN|CH|HS|CLASS[0-9]+)$");
const std::regex kTypeRe("^(?:TYPE[0-9]+|[A-Z0-9-]+)$");
const std::regex kBindViewRe("'([^']+)'");
const std::regex kBindCacheEntryRe("^([^/]+)/([^ ]+) \\[ttl ([0-9]+)\\]$");
const std::regex kClusterTokenRe("[^a-z0-9._-]+");
const std::regex kDnsmasqLogRe("^.*dnsmasq\\[[0-9]+\\]: (.*)$");
const std::regex kMaradnsFetchRe("^Fetching (.+) from cache$");
constexpr std::uint64_t kSmartdnsFileMagic = 0x6548634163536E44ULL;
constexpr std::uint32_t kSmartdnsRecordMagic = 0x64526352U;
constexpr std::uint32_t kSmartdnsDataMagic = 0x61546144U;

std::string trim(const std::string &Input) {
  const auto Begin = Input.find_first_not_of(" \t\r\n");
  if (Begin == std::string::npos) {
    return "";
  }
  const auto End = Input.find_last_not_of(" \t\r\n");
  return Input.substr(Begin, End - Begin + 1);
}

std::string joinTokens(const std::vector<std::string> &Tokens, size_t Start) {
  std::string Output;
  for (size_t Index = Start; Index < Tokens.size(); ++Index) {
    if (Tokens[Index].empty()) {
      continue;
    }
    if (!Output.empty()) {
      Output.push_back(' ');
    }
    Output += Tokens[Index];
  }
  return Output.empty() ? "_" : Output;
}

std::vector<std::string> splitWhitespace(const std::string &Input) {
  std::istringstream Stream(Input);
  std::vector<std::string> Output;
  std::string Token;
  while (Stream >> Token) {
    Output.push_back(Token);
  }
  return Output;
}

std::optional<size_t> findTtlIndex(const std::vector<std::string> &Tokens) {
  for (size_t Index = 0; Index < Tokens.size(); ++Index) {
    if (!Tokens[Index].empty() &&
        std::all_of(Tokens[Index].begin(), Tokens[Index].end(), ::isdigit)) {
      return Index;
    }
  }
  return std::nullopt;
}

bool isClassToken(const std::string &Token) {
  return std::regex_match(Token, kClassRe);
}

bool isTypeToken(std::string Token) {
  if (Token == "\\-") {
    return true;
  }
  if (Token.rfind("\\-", 0) == 0) {
    Token = Token.substr(2);
  }
  return !Token.empty() && std::regex_match(Token, kTypeRe);
}

bool looksLikeRrHeader(const std::string &Line) {
  const auto Stripped = trim(Line);
  if (Stripped.empty() || Stripped[0] == ';' || Stripped[0] == '$') {
    return false;
  }
  if (Stripped.rfind("msg ", 0) == 0) {
    return false;
  }
  const auto Tokens = splitWhitespace(Stripped);
  const auto TtlIndex = findTtlIndex(Tokens);
  if (!TtlIndex.has_value() || (*TtlIndex != 0 && *TtlIndex != 1)) {
    return false;
  }
  size_t TypeIndex = *TtlIndex + 1;
  if (TypeIndex < Tokens.size() && isClassToken(Tokens[TypeIndex])) {
    ++TypeIndex;
  }
  return TypeIndex < Tokens.size() && isTypeToken(Tokens[TypeIndex]);
}

std::string composeFlags(
    const std::vector<std::pair<std::string, std::string>> &Parts) {
  std::string Output;
  for (const auto &[Key, Value] : Parts) {
    if (Value.empty() || Value == "_") {
      continue;
    }
    if (!Output.empty()) {
      Output.push_back(' ');
    }
    Output += Key + "=" + Value;
  }
  return Output.empty() ? "_" : Output;
}

std::optional<std::tuple<CacheRecord, std::string, std::string>>
buildRrsetRecord(const std::string &Resolver, const std::string &View,
                 const std::string &Section, const std::string &PendingRrset,
                 const std::string &LastOwner, const std::string &LastClass) {
  const auto Tokens = splitWhitespace(trim(PendingRrset));
  const auto TtlIndex = findTtlIndex(Tokens);
  if (!TtlIndex.has_value() || (*TtlIndex != 0 && *TtlIndex != 1)) {
    return std::nullopt;
  }

  std::string Owner = *TtlIndex == 1 ? Tokens[0] : (LastOwner.empty() ? "_" : LastOwner);
  size_t TypeIndex = *TtlIndex + 1;
  std::string ClassToken = LastClass.empty() ? "_" : LastClass;
  if (TypeIndex < Tokens.size() && isClassToken(Tokens[TypeIndex])) {
    ClassToken = Tokens[TypeIndex];
    ++TypeIndex;
  }
  if (TypeIndex >= Tokens.size() || !isTypeToken(Tokens[TypeIndex])) {
    return std::nullopt;
  }

  const std::string Rrtype = Tokens[TypeIndex];
  const std::string Ttl = Tokens[*TtlIndex];
  const std::string Rdata = joinTokens(Tokens, TypeIndex + 1);
  CacheRecord Record{
      Resolver,
      View,
      Owner,
      Rrtype,
      Rrtype,
      Section,
      Rrtype.rfind("\\-", 0) == 0 ? "negative" : "rrset",
      Ttl,
      Rdata,
      composeFlags({{"class", ClassToken}}),
  };
  return std::make_tuple(Record, Owner == "_" ? LastOwner : Owner,
                         ClassToken == "_" ? LastClass : ClassToken);
}

std::optional<CacheRecord> buildUnboundMsgRecord(const std::string &Line) {
  const auto Tokens = splitWhitespace(trim(Line));
  if (Tokens.size() < 12) {
    return std::nullopt;
  }
  return CacheRecord{
      "unbound",
      "_",
      Tokens[1],
      Tokens[3],
      "_",
      "MSG",
      "message",
      Tokens[6],
      "_",
      composeFlags({{"class", Tokens[2]},
                    {"flags", Tokens[4]},
                    {"qd", Tokens[5]},
                    {"sec", Tokens[7]},
                    {"an", Tokens[8]},
                    {"ns", Tokens[9]},
                    {"ar", Tokens[10]},
                    {"bogus", Tokens[11]},
                    {"reason", joinTokens(Tokens, 12)}}),
  };
}

std::optional<CacheRecord> buildBindCacheEntryRecord(const std::string &View,
                                                     const std::string &Section,
                                                     const std::string &Line) {
  const std::string Entry = Line.substr(2);
  std::smatch Match;
  if (!std::regex_match(Entry, Match, kBindCacheEntryRe)) {
    return std::nullopt;
  }
  return CacheRecord{"bind9", View, Match[1], Match[2], "_", Section,
                     Section == "SERVFAIL" ? "servfail" : "badcache",
                     Match[3], "_", "_"};
}

template <typename T>
T readLittle(const std::vector<std::uint8_t> &Bytes, size_t Offset) {
  if (Offset + sizeof(T) > Bytes.size()) {
    throw std::runtime_error("smartdns cache 二进制截断");
  }
  T Value{};
  std::memcpy(&Value, Bytes.data() + Offset, sizeof(T));
  return Value;
}

std::string smartdnsQtypeName(int Qtype) {
  switch (Qtype) {
  case 1:
    return "A";
  case 5:
    return "CNAME";
  case 6:
    return "SOA";
  case 12:
    return "PTR";
  case 16:
    return "TXT";
  case 28:
    return "AAAA";
  case 33:
    return "SRV";
  case 65:
    return "HTTPS";
  case 257:
    return "CAA";
  default:
    return "TYPE" + std::to_string(Qtype);
  }
}

std::pair<std::string, size_t>
decodeDnsName(const std::vector<std::uint8_t> &Packet, size_t Offset) {
  std::vector<std::string> Labels;
  std::set<size_t> Seen;
  bool Jumped = false;
  size_t Cursor = Offset;
  size_t NextOffset = Offset;
  while (Cursor < Packet.size()) {
    const auto Length = Packet[Cursor];
    if (Length == 0) {
      if (!Jumped) {
        NextOffset = Cursor + 1;
      }
      std::string Name;
      for (size_t Index = 0; Index < Labels.size(); ++Index) {
        if (Index != 0) {
          Name.push_back('.');
        }
        Name += Labels[Index];
      }
      return {Name.empty() ? "." : Name, NextOffset};
    }
    if ((Length & 0xC0U) == 0xC0U) {
      if (Cursor + 1 >= Packet.size()) {
        throw std::runtime_error("smartdns cache 名称指针截断");
      }
      const size_t Pointer =
          static_cast<size_t>(((Length & 0x3FU) << 8U) | Packet[Cursor + 1]);
      if (!Seen.insert(Pointer).second) {
        throw std::runtime_error("smartdns cache 名称指针循环");
      }
      if (!Jumped) {
        NextOffset = Cursor + 2;
      }
      Cursor = Pointer;
      Jumped = true;
      continue;
    }
    ++Cursor;
    if (Cursor + Length > Packet.size()) {
      throw std::runtime_error("smartdns cache 标签截断");
    }
    Labels.emplace_back(reinterpret_cast<const char *>(Packet.data() + Cursor),
                        Length);
    Cursor += Length;
    if (!Jumped) {
      NextOffset = Cursor;
    }
  }
  throw std::runtime_error("smartdns cache 域名解析失败");
}

std::string smartdnsRdataText(const std::vector<std::uint8_t> &Packet,
                              size_t Offset, std::uint16_t Rrtype,
                              std::uint16_t Rdlength) {
  if (Offset + Rdlength > Packet.size()) {
    throw std::runtime_error("smartdns cache RDATA 截断");
  }
  if (Rrtype == 1 && Rdlength == 4) {
    return std::to_string(Packet[Offset]) + "." +
           std::to_string(Packet[Offset + 1]) + "." +
           std::to_string(Packet[Offset + 2]) + "." +
           std::to_string(Packet[Offset + 3]);
  }
  if (Rrtype == 28 && Rdlength == 16) {
    std::ostringstream Stream;
    Stream << std::hex;
    for (size_t Index = 0; Index < 8; ++Index) {
      if (Index != 0) {
        Stream << ":";
      }
      const auto Group = static_cast<unsigned int>(
          (Packet[Offset + (Index * 2)] << 8) |
          Packet[Offset + (Index * 2) + 1]);
      Stream << Group;
    }
    return Stream.str();
  }
  if (Rrtype == 5 || Rrtype == 12) {
    return decodeDnsName(Packet, Offset).first;
  }
  std::ostringstream Stream;
  Stream << std::hex;
  for (size_t Index = 0; Index < Rdlength; ++Index) {
    Stream << std::setw(2) << std::setfill('0')
           << static_cast<unsigned int>(Packet[Offset + Index]);
  }
  return Stream.str().empty() ? "_" : Stream.str();
}

bool looksLikeIpv4(const std::string &Token) {
  std::vector<std::string> Parts;
  std::string Current;
  std::istringstream Stream(Token);
  while (std::getline(Stream, Current, '.')) {
    Parts.push_back(Current);
  }
  return Parts.size() == 4U && std::all_of(Parts.begin(), Parts.end(), [](const std::string &Part) {
           return !Part.empty() &&
                  std::all_of(Part.begin(), Part.end(), ::isdigit);
         });
}

bool looksLikeIpv6(const std::string &Token) {
  return Token.find(':') != std::string::npos;
}

std::string stripDnsmasqLogPrefix(const std::string &Line) {
  std::smatch Match;
  const auto Stripped = trim(Line);
  if (std::regex_match(Stripped, Match, kDnsmasqLogRe)) {
    return Match[1].str();
  }
  return Stripped;
}

std::vector<CacheRecord> iterUnboundRecords(const std::vector<std::string> &Lines) {
  std::vector<CacheRecord> Records;
  std::string Section;
  std::string PendingRrset;
  std::string LastOwner;
  std::string LastClass;

  const auto FlushPending = [&]() {
    if (PendingRrset.empty()) {
      return;
    }
    const auto Built =
        buildRrsetRecord("unbound", "_", "RRSET", PendingRrset, LastOwner, LastClass);
    PendingRrset.clear();
    if (!Built.has_value()) {
      return;
    }
    Records.push_back(std::get<0>(*Built));
    LastOwner = std::get<1>(*Built);
    LastClass = std::get<2>(*Built);
  };

  for (const auto &Raw : Lines) {
    const std::string Line = Raw;
    const std::string Stripped = trim(Line);
    if (Line == "START_RRSET_CACHE") {
      Section = "RRSET";
      LastOwner.clear();
      LastClass.clear();
      continue;
    }
    if (Line == "START_MSG_CACHE") {
      FlushPending();
      Section = "MSG";
      continue;
    }
    if (Line.rfind("END_", 0) == 0 || Line == "EOF" || Stripped.empty()) {
      FlushPending();
      continue;
    }
    if (Section == "MSG" && Line.rfind("msg ", 0) == 0) {
      const auto Record = buildUnboundMsgRecord(Line);
      if (Record.has_value()) {
        Records.push_back(*Record);
      }
      continue;
    }
    if (Section == "MSG") {
      continue;
    }
    if (Section == "RRSET" && Line.rfind(";rrset", 0) == 0) {
      FlushPending();
      LastOwner.clear();
      LastClass.clear();
      continue;
    }
    if (Section == "RRSET" && Line.rfind(";", 0) == 0) {
      FlushPending();
      continue;
    }
    if (Section == "RRSET" && looksLikeRrHeader(Line)) {
      FlushPending();
      PendingRrset = Line;
      continue;
    }
    if (Section == "RRSET" && !PendingRrset.empty()) {
      PendingRrset += " " + Stripped;
    }
  }

  FlushPending();
  return Records;
}

std::vector<CacheRecord> iterDnsmasqRecords(const std::vector<std::string> &Lines) {
  std::vector<CacheRecord> Records;
  bool InCacheDump = false;

  for (const auto &Raw : Lines) {
    const std::string Line = stripDnsmasqLogPrefix(Raw);
    if (Line.rfind("Host ", 0) == 0 && Line.find("Address") != std::string::npos &&
        Line.find("Flags") != std::string::npos) {
      InCacheDump = true;
      continue;
    }
    if (!InCacheDump) {
      continue;
    }
    if (Line.rfind("------------------------------", 0) == 0) {
      continue;
    }
    if (Line.rfind("exiting on receipt of SIGTERM", 0) == 0) {
      break;
    }
    const auto Tokens = splitWhitespace(Line);
    if (Tokens.size() < 3U) {
      continue;
    }
    if (Tokens[0] == "bind") {
      continue;
    }
    std::string Rrtype = "_";
    if (looksLikeIpv4(Tokens[1])) {
      Rrtype = "A";
    } else if (looksLikeIpv6(Tokens[1])) {
      Rrtype = "AAAA";
    }
    Records.push_back(CacheRecord{
        "dnsmasq",
        "_",
        Tokens[0],
        Rrtype,
        Rrtype,
        "CACHE",
        "rrset",
        "_",
        Tokens[1],
        composeFlags({{"flags", Tokens[2]},
                      {"expires", joinTokens(Tokens, 3)}}),
    });
  }

  return Records;
}

std::string decodeMaradnsName(const std::string &Encoded) {
  std::vector<std::uint8_t> Raw(Encoded.begin(), Encoded.end());
  std::vector<std::uint8_t> Decoded;
  for (size_t Index = 0; Index < Raw.size();) {
    if (Raw[Index] == '\\' && Index + 3 < Raw.size() &&
        std::isdigit(Raw[Index + 1]) && std::isdigit(Raw[Index + 2]) &&
        std::isdigit(Raw[Index + 3])) {
      const int Value = (Raw[Index + 1] - '0') * 100 +
                        (Raw[Index + 2] - '0') * 10 +
                        (Raw[Index + 3] - '0');
      Decoded.push_back(static_cast<std::uint8_t>(Value));
      Index += 4;
      continue;
    }
    Decoded.push_back(Raw[Index]);
    ++Index;
  }
  std::string Name;
  for (size_t Cursor = 0; Cursor < Decoded.size();) {
    const auto Length = Decoded[Cursor];
    if (Length == 0) {
      break;
    }
    ++Cursor;
    if (Cursor + Length > Decoded.size()) {
      break;
    }
    if (!Name.empty()) {
      Name.push_back('.');
    }
    Name.append(reinterpret_cast<const char *>(Decoded.data() + Cursor), Length);
    Cursor += Length;
  }
  return Name;
}

std::vector<CacheRecord> iterMaradnsRecords(const std::vector<std::string> &Lines) {
  std::vector<CacheRecord> Records;
  for (const auto &Raw : Lines) {
    const auto Line = trim(Raw);
    if (Line.rfind("CACHE_ENTRY\t", 0) == 0) {
      const auto Tokens = splitWhitespace(
          std::regex_replace(Line, std::regex("\t"), " "));
      if (Tokens.size() >= 4U) {
        Records.push_back(CacheRecord{
            "maradns",
            "_",
            Tokens[1],
            Tokens[2],
            Tokens[2],
            "CACHE",
            "rrset",
            "_",
            Tokens[3],
            "source=deadwood-log",
        });
      }
      continue;
    }
    std::smatch Match;
    if (!std::regex_match(Line, Match, kMaradnsFetchRe)) {
      continue;
    }
    Records.push_back(CacheRecord{
        "maradns",
        "_",
        decodeMaradnsName(Match[1].str()),
        "A",
        "A",
        "CACHE",
        "rrset",
        "_",
        "_",
        "source=deadwood-log",
    });
  }
  return Records;
}

std::vector<CacheRecord>
iterKnotResolverRecords(const std::vector<std::string> &Lines) {
  std::vector<CacheRecord> Records;
  for (const auto &Raw : Lines) {
    const auto Line = trim(Raw);
    if (Line.rfind("CACHE_ENTRY\t", 0) != 0) {
      continue;
    }
    const auto Tokens =
        splitWhitespace(std::regex_replace(Line, std::regex("\t"), " "));
    if (Tokens.size() < 4U) {
      continue;
    }
    Records.push_back(CacheRecord{
        "knot-resolver",
        "_",
        Tokens[1],
        Tokens[2],
        Tokens[2],
        "CACHE",
        "rrset",
        "_",
        Tokens[3],
        "source=kresd-harness",
    });
  }
  return Records;
}

std::vector<CacheRecord> iterSmartdnsRecords(
    const std::vector<std::uint8_t> &Bytes) {
  if (Bytes.size() < 48U) {
    throw std::runtime_error("smartdns cache 文件过短");
  }
  if (readLittle<std::uint64_t>(Bytes, 0) != kSmartdnsFileMagic) {
    throw std::runtime_error("smartdns cache 文件 magic 非法");
  }
  const auto CacheNumber = readLittle<std::uint32_t>(Bytes, 40);
  size_t Offset = 48;
  std::vector<CacheRecord> Records;
  for (std::uint32_t Index = 0; Index < CacheNumber; ++Index) {
    if (Offset + 352U + 24U > Bytes.size()) {
      throw std::runtime_error("smartdns cache record 截断");
    }
    if (readLittle<std::uint32_t>(Bytes, Offset) != kSmartdnsRecordMagic) {
      throw std::runtime_error("smartdns cache record magic 非法");
    }
    const size_t InfoBase = Offset + 8U;
    const auto DomainBytes = std::string(
        reinterpret_cast<const char *>(Bytes.data() + InfoBase), 256U);
    const auto Domain = DomainBytes.substr(0, DomainBytes.find('\0'));
    const auto Qtype = readLittle<std::int32_t>(Bytes, InfoBase + 256U);
    const auto QueryFlag = readLittle<std::uint32_t>(Bytes, InfoBase + 292U);
    const auto Ttl = readLittle<std::int32_t>(Bytes, InfoBase + 296U);
    const auto Rcode = readLittle<std::int32_t>(Bytes, InfoBase + 300U);
    const auto Hitnum = readLittle<std::int32_t>(Bytes, InfoBase + 304U);
    const auto Speed = readLittle<std::int32_t>(Bytes, InfoBase + 308U);
    const auto InsertTime = readLittle<std::int64_t>(Bytes, InfoBase + 328U);
    const auto ReplaceTime = readLittle<std::int64_t>(Bytes, InfoBase + 336U);

    const size_t DataBase = Offset + 352U;
    if (readLittle<std::uint32_t>(Bytes, DataBase + 16U) != kSmartdnsDataMagic) {
      throw std::runtime_error("smartdns cache data magic 非法");
    }
    const auto DataSize = readLittle<std::int64_t>(Bytes, DataBase + 8U);
    if (DataSize < 0) {
      throw std::runtime_error("smartdns cache data size 非法");
    }
    const size_t PayloadOffset = DataBase + 24U;
    const size_t PayloadEnd = PayloadOffset + static_cast<size_t>(DataSize);
    if (PayloadEnd > Bytes.size()) {
      throw std::runtime_error("smartdns cache payload 截断");
    }
    std::vector<std::uint8_t> Packet(Bytes.begin() + PayloadOffset,
                                     Bytes.begin() + PayloadEnd);

    bool AddedAnswer = false;
    if (Packet.size() >= 12U) {
      const auto Qdcount = static_cast<size_t>((Packet[4] << 8) | Packet[5]);
      const auto Ancount = static_cast<size_t>((Packet[6] << 8) | Packet[7]);
      size_t Cursor = 12U;
      for (size_t QIndex = 0; QIndex < Qdcount; ++QIndex) {
        Cursor = decodeDnsName(Packet, Cursor).second + 4U;
      }
      for (size_t AIndex = 0; AIndex < Ancount; ++AIndex) {
        const auto [Name, NameEnd] = decodeDnsName(Packet, Cursor);
        Cursor = NameEnd;
        if (Cursor + 10U > Packet.size()) {
          throw std::runtime_error("smartdns cache answer 截断");
        }
        const auto Rrtype =
            static_cast<std::uint16_t>((Packet[Cursor] << 8) | Packet[Cursor + 1]);
        Cursor += 2U;
        const auto Rrclass =
            static_cast<std::uint16_t>((Packet[Cursor] << 8) | Packet[Cursor + 1]);
        Cursor += 2U;
        const auto Rrttl = static_cast<std::uint32_t>(
            (Packet[Cursor] << 24) | (Packet[Cursor + 1] << 16) |
            (Packet[Cursor + 2] << 8) | Packet[Cursor + 3]);
        Cursor += 4U;
        const auto Rdlength =
            static_cast<std::uint16_t>((Packet[Cursor] << 8) | Packet[Cursor + 1]);
        Cursor += 2U;
        const auto Rdata = smartdnsRdataText(Packet, Cursor, Rrtype, Rdlength);
        Cursor += Rdlength;
        Records.push_back(CacheRecord{
            "smartdns",
            "_",
            Name == "." ? Domain : Name,
            smartdnsQtypeName(Qtype),
            smartdnsQtypeName(Rrtype),
            "CACHE",
            "packet",
            std::to_string(Rrttl > 0 ? Rrttl : Ttl),
            Rdata,
            composeFlags({{"class", std::to_string(Rrclass)},
                          {"rcode", std::to_string(Rcode)},
                          {"hitnum", std::to_string(Hitnum)},
                          {"speed", std::to_string(Speed)},
                          {"query_flag", std::to_string(QueryFlag)},
                          {"insert_time", std::to_string(InsertTime)},
                          {"replace_time", std::to_string(ReplaceTime)}}),
        });
        AddedAnswer = true;
      }
    }
    if (!AddedAnswer) {
      Records.push_back(CacheRecord{
          "smartdns",
          "_",
          Domain,
          smartdnsQtypeName(Qtype),
          "_",
          "CACHE",
          "packet",
          std::to_string(Ttl),
          "_",
          composeFlags({{"rcode", std::to_string(Rcode)},
                        {"hitnum", std::to_string(Hitnum)},
                        {"speed", std::to_string(Speed)},
                        {"query_flag", std::to_string(QueryFlag)},
                        {"insert_time", std::to_string(InsertTime)},
                        {"replace_time", std::to_string(ReplaceTime)}}),
      });
    }
    Offset = PayloadEnd;
  }
  return Records;
}

std::vector<CacheRecord> iterBind9Records(const std::vector<std::string> &Lines) {
  std::vector<CacheRecord> Records;
  std::string View = "_";
  std::string Section = "RRSET";
  std::string PendingRrset;
  std::string LastOwner;
  std::string LastClass;

  const auto FlushPending = [&]() {
    if (PendingRrset.empty()) {
      return;
    }
    const auto Built =
        buildRrsetRecord("bind9", View, Section, PendingRrset, LastOwner, LastClass);
    PendingRrset.clear();
    if (!Built.has_value()) {
      return;
    }
    if (Section != "ADB") {
      Records.push_back(std::get<0>(*Built));
    }
    LastOwner = std::get<1>(*Built);
    LastClass = std::get<2>(*Built);
  };

  for (const auto &Raw : Lines) {
    const std::string Line = Raw;
    const std::string Stripped = trim(Line);
    if (Line.rfind("; Cache dump of view ", 0) == 0) {
      FlushPending();
      std::smatch Match;
      View = std::regex_search(Line, Match, kBindViewRe) ? Match[1].str() : "_";
      Section = "RRSET";
      LastOwner.clear();
      LastClass.clear();
      continue;
    }
    if (Line == "; Address database dump") {
      FlushPending();
      Section = "ADB";
      LastOwner.clear();
      LastClass.clear();
      continue;
    }
    if (Line == "; Bad cache") {
      FlushPending();
      Section = "BADCACHE";
      continue;
    }
    if (Line == "; SERVFAIL cache") {
      FlushPending();
      Section = "SERVFAIL";
      continue;
    }
    if (Line.rfind("$DATE", 0) == 0 || Line.rfind("; using ", 0) == 0 ||
        Line.rfind("; [edns success/timeout]", 0) == 0 ||
        Line.rfind("; [plain success/timeout]", 0) == 0 || Line == ";" ||
        Stripped.empty()) {
      FlushPending();
      continue;
    }
    if (Section == "SERVFAIL" && Line.rfind("; ", 0) == 0) {
      FlushPending();
      const auto Record = buildBindCacheEntryRecord(View, Section, Line);
      if (Record.has_value()) {
        Records.push_back(*Record);
      }
      continue;
    }
    if (Section == "BADCACHE" && Line.rfind("; ", 0) == 0) {
      FlushPending();
      const auto Record = buildBindCacheEntryRecord(View, Section, Line);
      if (Record.has_value()) {
        Records.push_back(*Record);
      }
      continue;
    }
    if (Line.rfind(";", 0) == 0) {
      FlushPending();
      continue;
    }
    if (looksLikeRrHeader(Line)) {
      FlushPending();
      PendingRrset = Line;
      continue;
    }
    if (!PendingRrset.empty()) {
      PendingRrset += " " + Stripped;
    }
  }

  FlushPending();
  return Records;
}

std::string canonicalResolver(std::string Resolver) {
  std::transform(Resolver.begin(), Resolver.end(), Resolver.begin(), ::tolower);
  if (Resolver == "named") {
    return "bind9";
  }
  if (Resolver == "kresd") {
    return "knot-resolver";
  }
  return Resolver;
}

using StructuralKey = std::tuple<std::string, std::string, std::string, std::string,
                                 std::string, std::string, std::string, std::string,
                                 std::string>;

StructuralKey structuralKey(const CacheRecord &Record) {
  return {Record.Resolver,  Record.View,      Record.QName,
          Record.QType,     Record.RRType,    Record.Section,
          Record.CacheType, Record.RDataNorm, Record.Flags};
}

ResolverCacheDiff buildResolverCacheDiff(const std::vector<CacheRecord> &Before,
                                         const std::vector<CacheRecord> &After,
                                         bool IncludeDetails) {
  std::map<StructuralKey, int> BeforeCounter;
  std::map<StructuralKey, int> AfterCounter;
  for (const auto &Row : Before) {
    ++BeforeCounter[structuralKey(Row)];
  }
  for (const auto &Row : After) {
    ++AfterCounter[structuralKey(Row)];
  }

  ResolverCacheDiff Output;
  Output.EntriesBefore = static_cast<int>(Before.size());
  Output.EntriesAfter = static_cast<int>(After.size());
  Output.HasCacheDiff = BeforeCounter != AfterCounter;
  if (!IncludeDetails) {
    return Output;
  }

  std::set<StructuralKey> Keys;
  for (const auto &[Key, Count] : BeforeCounter) {
    (void)Count;
    Keys.insert(Key);
  }
  for (const auto &[Key, Count] : AfterCounter) {
    (void)Count;
    Keys.insert(Key);
  }

  for (const auto &Key : Keys) {
    const int BeforeCount = BeforeCounter[Key];
    const int AfterCount = AfterCounter[Key];
    if (BeforeCount == AfterCount) {
      continue;
    }
    CacheDeltaItem Item;
    Item.Kind = AfterCount > BeforeCount ? "added" : "removed";
    Item.CountBefore = BeforeCount;
    Item.CountAfter = AfterCount;
    Item.Delta = std::abs(AfterCount - BeforeCount);
    Item.Fields = {
        std::get<0>(Key), std::get<1>(Key), std::get<2>(Key), std::get<3>(Key),
        std::get<4>(Key), std::get<5>(Key), std::get<6>(Key), "_",
        std::get<7>(Key), std::get<8>(Key),
    };
    Output.DeltaItems.push_back(Item);
  }

  Output.InterestingDeltaCount = static_cast<int>(Output.DeltaItems.size());
  return Output;
}

std::optional<bool> objectBool(const json::Value::Object &Object,
                               const std::string &Key) {
  const auto Found = Object.find(Key);
  if (Found == Object.end()) {
    return std::nullopt;
  }
  if (const auto *BoolValue = std::get_if<bool>(&Found->second.storage())) {
    return *BoolValue;
  }
  return std::nullopt;
}

std::optional<std::string> objectString(const json::Value::Object &Object,
                                        const std::string &Key) {
  const auto Found = Object.find(Key);
  if (Found == Object.end()) {
    return std::nullopt;
  }
  if (const auto *StringValue =
          std::get_if<std::string>(&Found->second.storage())) {
    return *StringValue;
  }
  return std::nullopt;
}

std::vector<std::string> oracleDiffFields(const json::Value::Object &Oracle) {
  std::vector<std::string> Fields;
  for (const auto &Field : {"parse_ok", "resolver_fetch_started",
                            "response_accepted", "second_query_hit",
                            "cache_entry_created", "timeout"}) {
    if (objectBool(Oracle, "bind9." + std::string(Field)) !=
        objectBool(Oracle, "unbound." + std::string(Field))) {
      Fields.push_back(Field);
    }
  }
  return Fields;
}

bool cacheHasDiff(const CacheDiffResult &Input) {
  return Input.Bind9.HasCacheDiff || Input.Unbound.HasCacheDiff;
}

int interestingDeltaCount(const CacheDiffResult &Input) {
  return Input.Bind9.InterestingDeltaCount + Input.Unbound.InterestingDeltaCount;
}

std::string clusterToken(const std::string &Value) {
  std::string Text = Value;
  std::transform(Text.begin(), Text.end(), Text.begin(), ::tolower);
  Text = std::regex_replace(Text, kClusterTokenRe, "-");
  while (!Text.empty() && Text.front() == '-') {
    Text.erase(Text.begin());
  }
  while (!Text.empty() && Text.back() == '-') {
    Text.pop_back();
  }
  return Text.empty() ? "_" : Text;
}

TriageRecord projectionFromStatus(const std::string &Status,
                                  const std::string &DiffClass,
                                  bool NeedsManualReview) {
  TriageRecord Output;
  Output.Status = Status;
  Output.DiffClass = DiffClass;
  if (DiffClass == "oracle_and_cache_diff" || DiffClass == "oracle_diff" ||
      DiffClass == "cache_diff_interesting") {
    Output.AnalysisState = "included";
    Output.SemanticOutcome = DiffClass;
    Output.FailureBucketPrimary = "semantic_diff";
    Output.FailureBucketDetail = DiffClass;
    Output.OracleAuditCandidate = true;
  } else if (DiffClass == "cache_diff_benign" || DiffClass == "no_diff") {
    Output.AnalysisState = "included";
    Output.SemanticOutcome = DiffClass;
    Output.FailureBucketPrimary = "valid_negative";
    Output.FailureBucketDetail = DiffClass;
  } else if (DiffClass == "oracle_parse_incomplete") {
    Output.AnalysisState = "unknown";
    Output.SemanticOutcome = "runtime_or_parse_failure";
    Output.FailureBucketPrimary = "input_parse_failure";
    Output.FailureBucketDetail = DiffClass;
    Output.OracleAuditCandidate = false;
  } else if (DiffClass == "replay_missing_artifact" ||
             DiffClass == "replay_missing_executable") {
    Output.AnalysisState = "excluded";
    Output.ExcludeReason = "infra_failure";
    Output.SemanticOutcome = "infra_failure";
    Output.FailureBucketPrimary = "infra_artifact_failure";
    Output.FailureBucketDetail = DiffClass;
  } else if (DiffClass == "replay_subprocess_launch_error") {
    Output.AnalysisState = "excluded";
    Output.ExcludeReason = "infra_failure";
    Output.SemanticOutcome = "infra_failure";
    Output.FailureBucketPrimary = "orchestrator_compat_failure";
    Output.FailureBucketDetail = DiffClass;
  } else {
    Output.AnalysisState = "unknown";
    Output.SemanticOutcome = "runtime_or_parse_failure";
    Output.FailureBucketPrimary = "target_runtime_failure";
    Output.FailureBucketDetail = DiffClass.empty() ? "replay_subprocess_failed"
                                                   : DiffClass;
  }
  Output.CaseStudyCandidate = Output.OracleAuditCandidate && NeedsManualReview;
  Output.ManualTruthStatus =
      Output.OracleAuditCandidate ? "not_started" : "not_applicable";
  return Output;
}

} // namespace

std::vector<std::string> CacheRecord::toFields() const {
  return {Resolver, View, QName, QType, RRType, Section,
          CacheType, TTL, RDataNorm, Flags};
}

std::vector<CacheRecord> parseCacheDump(const std::string &Resolver,
                                        const std::filesystem::path &DumpPath) {
  if (!std::filesystem::is_regular_file(DumpPath)) {
    throw std::runtime_error("cache dump 文件不存在: " + DumpPath.string());
  }
  const auto Canonical = canonicalResolver(Resolver);
  if (Canonical == "smartdns") {
    std::ifstream Input(DumpPath, std::ios::binary);
    std::vector<std::uint8_t> Bytes((std::istreambuf_iterator<char>(Input)),
                                    std::istreambuf_iterator<char>());
    return iterSmartdnsRecords(Bytes);
  }
  std::ifstream Input(DumpPath);
  std::vector<std::string> Lines;
  std::string Line;
  while (std::getline(Input, Line)) {
    Lines.push_back(Line);
  }

  if (Canonical == "unbound") {
    return iterUnboundRecords(Lines);
  }
  if (Canonical == "bind9") {
    return iterBind9Records(Lines);
  }
  if (Canonical == "maradns") {
    return iterMaradnsRecords(Lines);
  }
  if (Canonical == "dnsmasq") {
    return iterDnsmasqRecords(Lines);
  }
  if (Canonical == "knot-resolver") {
    return iterKnotResolverRecords(Lines);
  }
  throw std::runtime_error("未知 resolver: " + Resolver);
}

CacheDiffResult buildCacheDiff(const std::string &SampleId,
                               const std::vector<CacheRecord> &Bind9Before,
                               const std::vector<CacheRecord> &Bind9After,
                               const std::vector<CacheRecord> &UnboundBefore,
                               const std::vector<CacheRecord> &UnboundAfter,
                               bool Triggered) {
  CacheDiffResult Output;
  Output.SampleId = SampleId;
  Output.CacheDeltaTriggered = Triggered;
  Output.Bind9 = buildResolverCacheDiff(Bind9Before, Bind9After, Triggered);
  Output.Unbound = buildResolverCacheDiff(UnboundBefore, UnboundAfter, Triggered);
  return Output;
}

TriageRecord buildTriageRecord(const std::string &SampleId,
                               const json::Value::Object &OraclePayload,
                               const CacheDiffResult &CacheDiff,
                               const StateFingerprint &Fingerprint,
                               const std::optional<FailureEvidence> &Failure) {
  TriageRecord Output;
  Output.SampleId = SampleId;
  Output.GeneratedAt = utcTimestampNow();
  Output.CacheDeltaTriggered = CacheDiff.CacheDeltaTriggered;
  Output.InterestingDeltaCount = interestingDeltaCount(CacheDiff);

  const auto Bind9Status = objectString(OraclePayload, "bind9.stderr_parse_status");
  const auto UnboundStatus =
      objectString(OraclePayload, "unbound.stderr_parse_status");
  const auto DiffFields = oracleDiffFields(OraclePayload);

  std::vector<std::string> Notes;
  std::vector<std::string> Labels;
  bool NeedsManualReview = false;
  std::string Status;
  std::string DiffClass;

  if (!Bind9Status.has_value() && !UnboundStatus.has_value()) {
    Status = "failed_replay";
    if (Failure.has_value() && Failure->Reason.has_value()) {
      if (*Failure->Reason == "missing_artifact") {
        DiffClass = "replay_missing_artifact";
      } else if (*Failure->Reason == "missing_executable") {
        DiffClass = "replay_missing_executable";
      } else if (*Failure->Reason == "subprocess_launch_error") {
        DiffClass = "replay_subprocess_launch_error";
      } else if (*Failure->Reason == "timeout") {
        DiffClass = "replay_timeout";
      } else {
        DiffClass = "replay_subprocess_failed";
      }
    } else {
      DiffClass = "replay_subprocess_failed";
    }
    Labels.push_back("oracle_missing");
    Notes.push_back("oracle.json 缺失，当前样本按 replay 失败处理");
    NeedsManualReview = true;
  } else if (Bind9Status != std::optional<std::string>("ok") ||
             UnboundStatus != std::optional<std::string>("ok")) {
    Status = "failed_parse";
    DiffClass = "oracle_parse_incomplete";
    Labels.push_back("oracle_parse_incomplete");
    NeedsManualReview = true;
    Notes.push_back("oracle 解析不完整");
  } else if (!DiffFields.empty()) {
    Status = "completed_oracle_diff";
    DiffClass = cacheHasDiff(CacheDiff) ? "oracle_and_cache_diff" : "oracle_diff";
    Labels.push_back("oracle_diff");
    NeedsManualReview = true;
    Notes.push_back("oracle 字段存在 resolver 间差异");
  } else if (cacheHasDiff(CacheDiff)) {
    if (CacheDiff.CacheDeltaTriggered && Output.InterestingDeltaCount > 0) {
      Status = "completed_cache_changed_needs_review";
      DiffClass = "cache_diff_interesting";
      Labels.push_back("cache_diff_present");
      Labels.push_back("cache_delta_review");
      NeedsManualReview = true;
      Notes.push_back("cache 结构差异已触发明细输出");
    } else {
      Status = "completed_cache_changed_but_benign";
      DiffClass = "cache_diff_benign";
      Labels.push_back("cache_diff_present");
      Notes.push_back("cache 存在结构差异，但当前未命中需要人工复核的触发条件");
    }
  } else {
    Status = "completed_no_diff";
    DiffClass = "no_diff";
    Notes.push_back("oracle 与 cache_diff 均未发现需升级处理的结构化差异");
  }

  if (CacheDiff.CacheDeltaTriggered) {
    Labels.push_back("cache_delta_triggered");
  }
  if (Output.InterestingDeltaCount > 0) {
    Labels.push_back("cache_delta_items_present");
  }

  const auto Bind9Forwarding = Fingerprint.Bind9ForwardingPath.value_or("_");
  const auto UnboundForwarding = Fingerprint.UnboundForwardingPath.value_or("_");
  if (Fingerprint.Bind9ForwardingPath.has_value() ||
      Fingerprint.UnboundForwardingPath.has_value()) {
    Labels.push_back("forwarding_path_seen");
  }
  if (Fingerprint.Bind9ForwardingPath.has_value() &&
      Fingerprint.UnboundForwardingPath.has_value() &&
      *Fingerprint.Bind9ForwardingPath != *Fingerprint.UnboundForwardingPath) {
    Labels.push_back("forwarding_path_mismatch");
    Notes.push_back("state_fingerprint 记录到 resolver forwarding_path 不一致");
    NeedsManualReview = true;
  }

  const auto Projection =
      projectionFromStatus(Status, DiffClass, NeedsManualReview);
  Output.Status = Projection.Status;
  Output.DiffClass = Projection.DiffClass;
  Output.AnalysisState = Projection.AnalysisState;
  Output.ExcludeReason = Projection.ExcludeReason;
  Output.SemanticOutcome = Projection.SemanticOutcome;
  Output.FailureTaxonomyVersion = Projection.FailureTaxonomyVersion;
  Output.FailureBucketPrimary = Projection.FailureBucketPrimary;
  Output.FailureBucketDetail = Projection.FailureBucketDetail;
  Output.OracleAuditCandidate = Projection.OracleAuditCandidate;
  Output.CaseStudyCandidate = Projection.CaseStudyCandidate;
  Output.ManualTruthStatus = Projection.ManualTruthStatus;
  Output.FilterLabels = Labels;
  Output.NeedsManualReview = NeedsManualReview;
  Output.Notes = Notes;

  std::string LabelToken;
  for (size_t Index = 0; Index < Labels.size(); ++Index) {
    if (Index != 0) {
      LabelToken.push_back(',');
    }
    LabelToken += clusterToken(Labels[Index]);
  }
  if (LabelToken.empty()) {
    LabelToken = "_";
  }
  Output.ClusterKey = clusterToken(Status) + "|" + clusterToken(DiffClass) + "|" +
                      LabelToken + "|fp:" + clusterToken(Bind9Forwarding) + "->" +
                      clusterToken(UnboundForwarding);
  return Output;
}

json::Value toJson(const CacheDeltaItem &Input) {
  json::Value::Object Output;
  Output["kind"] = Input.Kind;
  Output["count_before"] = Input.CountBefore;
  Output["count_after"] = Input.CountAfter;
  Output["delta"] = Input.Delta;
  json::Value::Object Fields;
  Fields["resolver"] = Input.Fields.Resolver;
  Fields["view"] = Input.Fields.View;
  Fields["qname"] = Input.Fields.QName;
  Fields["qtype"] = Input.Fields.QType;
  Fields["rrtype"] = Input.Fields.RRType;
  Fields["section"] = Input.Fields.Section;
  Fields["cache_type"] = Input.Fields.CacheType;
  Fields["rdata_norm"] = Input.Fields.RDataNorm;
  Fields["flags"] = Input.Fields.Flags;
  Output["fields"] = Fields;
  return Output;
}

json::Value toJson(const ResolverCacheDiff &Input) {
  json::Value::Object Output;
  Output["entries_before"] = Input.EntriesBefore;
  Output["entries_after"] = Input.EntriesAfter;
  Output["has_cache_diff"] = Input.HasCacheDiff;
  Output["interesting_delta_count"] = Input.InterestingDeltaCount;
  json::Value::Array DeltaItems;
  for (const auto &Item : Input.DeltaItems) {
    DeltaItems.emplace_back(toJson(Item));
  }
  Output["delta_items"] = DeltaItems;
  return Output;
}

json::Value toJson(const CacheDiffResult &Input) {
  json::Value::Object Output;
  Output["schema_version"] = kSchemaVersion;
  Output["generated_at"] = utcTimestampNow();
  Output["sample_id"] = Input.SampleId;
  Output["cache_delta_triggered"] = Input.CacheDeltaTriggered;
  Output["bind9"] = toJson(Input.Bind9);
  Output["unbound"] = toJson(Input.Unbound);
  return Output;
}

json::Value toJson(const TriageRecord &Input) {
  json::Value::Object Output;
  Output["schema_version"] = kSchemaVersion;
  Output["generated_at"] = Input.GeneratedAt;
  Output["sample_id"] = Input.SampleId;
  Output["status"] = Input.Status;
  Output["diff_class"] = Input.DiffClass;
  Output["analysis_state"] = Input.AnalysisState;
  json::setOptional(Output, "exclude_reason", Input.ExcludeReason);
  Output["semantic_outcome"] = Input.SemanticOutcome;
  Output["failure_taxonomy_version"] = Input.FailureTaxonomyVersion;
  Output["failure_bucket_primary"] = Input.FailureBucketPrimary;
  Output["failure_bucket_detail"] = Input.FailureBucketDetail;
  json::Value::Array Labels;
  for (const auto &Label : Input.FilterLabels) {
    Labels.emplace_back(Label);
  }
  Output["filter_labels"] = Labels;
  Output["cluster_key"] = Input.ClusterKey;
  Output["cache_delta_triggered"] = Input.CacheDeltaTriggered;
  Output["interesting_delta_count"] = Input.InterestingDeltaCount;
  Output["needs_manual_review"] = Input.NeedsManualReview;
  Output["oracle_audit_candidate"] = Input.OracleAuditCandidate;
  Output["case_study_candidate"] = Input.CaseStudyCandidate;
  Output["manual_truth_status"] = Input.ManualTruthStatus;
  json::Value::Array Notes;
  for (const auto &Note : Input.Notes) {
    Notes.emplace_back(Note);
  }
  Output["notes"] = Notes;
  return Output;
}

} // namespace dnslab
