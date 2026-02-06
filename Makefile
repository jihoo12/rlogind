# 컴파일러 설정
CC = gcc

# 컴파일 옵션 (경고 표시 포함)
CFLAGS = -Wall

# 링크할 라이브러리 (-lpam)
LIBS = -lpam

# 최종 실행 파일 이름
TARGET = rlogind

# 소스 파일
SRCS = main.c

# 빌드 규칙
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

# 정리 규칙 (make clean 실행 시)
clean:
	rm -f $(TARGET)
