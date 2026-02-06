#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <security/pam_appl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <paths.h> // _PATH_DEFPATH 사용

#define MAX_LEN 100

// [중요] 직접 niri를 실행하기보다 래퍼 스크립트를 권장합니다.
// 예: /usr/local/bin/start-niri.sh
#define SESSION_CMD "/usr/bin/niri" 
// 만약 스크립트를 쓴다면: "/usr/local/bin/start-niri.sh"

// 컬러 정의
#define COLOR_RESET  "\033[0m"
#define COLOR_BOLD   "\033[1m"
#define COLOR_CYAN   "\033[36m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_RED    "\033[31m"
#define COLOR_GRAY   "\033[90m"
#define HIDE_CURSOR  "\033[?25l"
#define SHOW_CURSOR  "\033[?25h"

pam_handle_t *pamh = NULL;
struct termios original_termios; // 초기 터미널 상태 저장용

// --- 시그널 및 터미널 관리 ---
void handle_signal(int sig) {
    // SIGINT 무시
}

void save_termios() {
    tcgetattr(STDIN_FILENO, &original_termios);
}

void restore_termios() {
    tcsetattr(STDIN_FILENO, TCSANOW, &original_termios);
}

// --- UI 유틸리티 ---
void clear_screen() {
    printf("\033[H\033[J");
}

void move_cursor(int x, int y) {
    printf("\033[%d;%dH", y, x);
}

void get_center(int *cols, int *rows) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) {
        *cols = 80; *rows = 24; // fallback
    } else {
        *cols = w.ws_col;
        *rows = w.ws_row;
    }
}

void draw_box(int width, int height) {
    int cols, rows;
    get_center(&cols, &rows);
    int start_x = (cols - width) / 2;
    int start_y = (rows - height) / 2;
    
    if (start_x < 1) start_x = 1;
    if (start_y < 1) start_y = 1;

    move_cursor(start_x, start_y);
    printf("┌──────────────────────────────────────────┐");
    for(int i = 1; i < height - 1; i++) {
        move_cursor(start_x, start_y + i);
        printf("│                                          │");
    }
    move_cursor(start_x, start_y + height - 1);
    printf("└──────────────────────────────────────────┘");
}

void get_password_input(char *buffer, int size) {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    if (fgets(buffer, size, stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
    } else {
        buffer[0] = 0;
    }
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

// --- PAM 관련 함수 ---
int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr) {
    char *pass = (char *)appdata_ptr;
    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (*resp == NULL) return PAM_BUF_ERR;
    
    for (int i = 0; i < num_msg; i++) {
        // 프롬프트(비밀번호 요청)인 경우에만 패스워드 전달
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            (*resp)[i].resp = strdup(pass);
            (*resp)[i].resp_retcode = 0;
        } else {
            // 정보성 메시지나 에러 메시지는 무시하거나 null 처리
            (*resp)[i].resp = NULL;
            (*resp)[i].resp_retcode = 0;
        }
    }
    return PAM_SUCCESS;
}

int authenticate_and_start_pam(const char *username, const char *password) {
    int retval;
    struct pam_conv conv = { pam_conversation, (void *)password };
    
    retval = pam_start("login", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) return 0;
    
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) { pam_end(pamh, retval); pamh = NULL; return 0; }
    
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) { pam_end(pamh, retval); pamh = NULL; return 0; }
    
    retval = pam_open_session(pamh, 0);
    if (retval != PAM_SUCCESS) { pam_end(pamh, retval); pamh = NULL; return 0; }
    
    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) { pam_close_session(pamh, 0); pam_end(pamh, retval); pamh = NULL; return 0; }
    
    return 1;
}

void close_pam_session() {
    if (pamh) {
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_close_session(pamh, 0);
        pam_end(pamh, PAM_SUCCESS);
        pamh = NULL;
    }
}

void ensure_runtime_dir(uid_t uid, gid_t gid) {
    char path[64];
    snprintf(path, sizeof(path), "/run/user/%d", uid);
    
    struct stat st;
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) == 0) {
            chown(path, uid, gid);
        }
    } else {
        // 이미 존재한다면 권한 확인 및 수정
        if ((st.st_mode & 0777) != 0700 || st.st_uid != uid) {
            chmod(path, 0700);
            chown(path, uid, gid);
        }
    }
}

void launch_session(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) return;

    // 환경변수 리스트 복사
    char **envlist = pam_getenvlist(pamh);
    
    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
    } else if (pid == 0) {
        // --- 자식 프로세스 (사용자 세션) ---
        
        // 1. PAM 환경변수 적용
        if (envlist) {
            for (int i = 0; envlist[i]; i++) {
                putenv(envlist[i]);
            }
        }

        // 2. 핵심 POSIX 및 XDG 환경변수 설정
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
        setenv("HOME", pw->pw_dir, 1);
        setenv("SHELL", pw->pw_shell, 1);
        
        // PATH가 없으면 기본값 설정 (매우 중요)
        if (getenv("PATH") == NULL) {
            setenv("PATH", _PATH_DEFPATH, 1); 
        }

        // Wayland 필수 변수
        setenv("XDG_SESSION_TYPE", "wayland", 1);
        setenv("XDG_SESSION_CLASS", "user", 1);
        setenv("XDG_SEAT", "seat0", 1); 
        // VT는 systemd-logind가 자동 관리하지만 명시적으로 필요할 수 있음
        
        // XDG_RUNTIME_DIR 설정
        char xdg_runtime_dir[64];
        if (getenv("XDG_RUNTIME_DIR") == NULL) {
            snprintf(xdg_runtime_dir, sizeof(xdg_runtime_dir), "/run/user/%d", pw->pw_uid);
            setenv("XDG_RUNTIME_DIR", xdg_runtime_dir, 1);
            ensure_runtime_dir(pw->pw_uid, pw->pw_gid);
        }

        // 3. 권한 변경 (순서 준수)
        initgroups(username, pw->pw_gid);
        setgid(pw->pw_gid);
        setuid(pw->pw_uid);

        // 4. 작업 디렉토리
        chdir(pw->pw_dir);

        // 5. 로그인 쉘을 통해 WM 실행
        // 이렇게 해야 .bash_profile 등이 로드됩니다.
        char *shell = pw->pw_shell;
        if (!shell || strlen(shell) == 0) shell = "/bin/sh";

        // 명령 구성: exec /usr/bin/niri
        // 'exec'를 붙여야 쉘 프로세스가 WM으로 대체되어 PID 관리가 깔끔해짐
        char cmd_buf[512];
        snprintf(cmd_buf, sizeof(cmd_buf), "exec %s", SESSION_CMD);

        // 쉘을 로그인 쉘(-l)로 실행하여 사용자 환경 설정을 읽어들임
        execl(shell, shell, "-l", "-c", cmd_buf, NULL);
        
        perror("Failed to execute session");
        exit(1);
    } else {
        // --- 부모 프로세스 ---
        int status;
        waitpid(pid, &status, 0); // 자식 종료 대기
        
        // 메모리 해제
        if (envlist) {
            for (int i = 0; envlist[i]; i++) free(envlist[i]);
            free(envlist);
        }
        
        // 터미널 상태 복구 (매우 중요: 그래픽 세션 종료 후 텍스트 모드 복구)
        restore_termios();
        // 화면 클리어 및 커서 복구
        printf("\033[H\033[J");
        printf(SHOW_CURSOR);
    }
}

// --- 메인 ---
int main() {
    char username[MAX_LEN];
    char password[MAX_LEN];
    char status_msg[256] = "";
    int msg_type = 0; 

    // 초기 상태 저장
    save_termios();
    
    // 시그널 핸들링
    signal(SIGINT, handle_signal);
    signal(SIGTSTP, SIG_IGN);

    if (geteuid() != 0) {
        fprintf(stderr, "Error: This program must be run as root.\n");
        return 1;
    }

    printf(HIDE_CURSOR);

    while (1) {
        int cols, rows;
        get_center(&cols, &rows);
        int mid_x = cols / 2;
        int mid_y = rows / 2;

        clear_screen();
        draw_box(44, 10);

        move_cursor(mid_x - 4, mid_y - 3);
        printf(COLOR_BOLD COLOR_CYAN "MY-LOGIN" COLOR_RESET);

        if (strlen(status_msg) > 0) {
            move_cursor(mid_x - (strlen(status_msg)/2), mid_y - 1);
            if (msg_type == 1) printf(COLOR_GREEN "%s" COLOR_RESET, status_msg);
            else if (msg_type == 2) printf(COLOR_RED "%s" COLOR_RESET, status_msg);
            else printf("%s", status_msg);
        }

        move_cursor(mid_x - 15, mid_y + 1);
        printf("User: [                ]");
        move_cursor(mid_x - 15, mid_y + 2);
        printf("Pass: [                ]");

        // 사용자 입력
        move_cursor(mid_x - 8, mid_y + 1);
        printf(SHOW_CURSOR);
        if (fgets(username, MAX_LEN, stdin) == NULL) {
            break; // EOF handling
        }
        printf(HIDE_CURSOR);
        
        username[strcspn(username, "\n")] = 0;
        if (strlen(username) == 0) continue;

        // 비밀번호 입력
        move_cursor(mid_x - 8, mid_y + 2);
        get_password_input(password, MAX_LEN);

        move_cursor(mid_x - 10, mid_y + 4);
        printf(COLOR_GRAY "Verifying..." COLOR_RESET);
        fflush(stdout);

        if (authenticate_and_start_pam(username, password)) {
            msg_type = 1;
            sprintf(status_msg, "Starting Session...");
            
            // 세션 시작 전 화면 정리
            clear_screen();
            printf(SHOW_CURSOR); // 세션에 커서 넘겨줌
            
            launch_session(username);
            
            // 세션 종료 후
            close_pam_session();
            
            // 로그아웃 후 복귀 처리
            printf(HIDE_CURSOR);
            msg_type = 0;
            status_msg[0] = 0; 
        } else {
            msg_type = 2;
            strcpy(status_msg, "Login Failed");
            sleep(2); // Brute-force 방지 딜레이
        }
        
        memset(password, 0, MAX_LEN);
        memset(username, 0, MAX_LEN);
    }

    restore_termios();
    printf(SHOW_CURSOR);
    return 0;
}
