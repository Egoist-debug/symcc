#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *Input;
static int Pos;
static int ParseError;

static int parse_expr(void);

static int peek(void) {
  return Input[Pos];
}

static int consume(void) {
  return Input[Pos++];
}

static int parse_number(void) {
  if (peek() < '0' || peek() > '9') {
    ParseError = 1;
    return 0;
  }
  int num = 0;
  while (peek() >= '0' && peek() <= '9') {
    num = num * 10 + (consume() - '0');
  }
  return num;
}

static int parse_factor(void) {
  if (ParseError) return 0;
  
  if (peek() == '(') {
    consume();
    int result = parse_expr();
    if (ParseError) return 0;
    if (peek() != ')') {
      ParseError = 1;
      return 0;
    }
    consume();
    return result;
  }
  
  if (peek() >= '0' && peek() <= '9') {
    return parse_number();
  }
  
  ParseError = 1;
  return 0;
}

static int parse_term(void) {
  if (ParseError) return 0;
  
  int left = parse_factor();
  if (ParseError) return 0;
  
  while (peek() == '*' || peek() == '/') {
    char op = consume();
    int right = parse_factor();
    if (ParseError) return 0;
    if (op == '*') {
      left *= right;
    } else if (right != 0) {
      left /= right;
    } else {
      ParseError = 1;
      return 0;
    }
  }
  
  return left;
}

static int parse_expr(void) {
  if (ParseError) return 0;
  
  int left = parse_term();
  if (ParseError) return 0;
  
  while (peek() == '+' || peek() == '-') {
    char op = consume();
    int right = parse_term();
    if (ParseError) return 0;
    if (op == '+') {
      left += right;
    } else {
      left -= right;
    }
  }
  
  return left;
}

int main(void) {
  char buf[256];
  ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
  if (n <= 0) {
    return 1;
  }
  buf[n] = '\0';
  
  if (n > 0 && buf[n-1] == '\n') {
    buf[n-1] = '\0';
    n--;
  }
  
  if (n == 0) {
    printf("FAIL: empty input\n");
    return 1;
  }
  
  Input = buf;
  Pos = 0;
  ParseError = 0;
  
  int result = parse_expr();
  
  if (ParseError) {
    printf("FAIL: parse error at position %d\n", Pos);
    return 1;
  }
  
  if (Input[Pos] != '\0') {
    printf("FAIL: unexpected character '%c' at position %d\n", Input[Pos], Pos);
    return 1;
  }
  
  printf("OK: %s = %d\n", buf, result);
  return 0;
}
