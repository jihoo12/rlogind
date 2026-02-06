#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <security/pam_appl.h>
#include <termios.h>
#include <sys/ioctl.h> // 화면 크기 계산용

#define MAX_LEN 100
#define WM_PATH "/usr/bin/niri"

// 컬러 정의
#define COLOR_RESET  "\033[0m"
#define COLOR_BOLD   "\033[1m"
#define COLOR_CYAN   "\033[36m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_RED    "\033[31m"
#define COLOR_GRAY   "\033[90m"

pam_handle_t *pamh = NULL;

// --- UI 유틸리티 ---
void clear_screen() {
    printf("\033[H\033[J");
}

void move_cursor(int x, int y) {
    printf("\033[%d;%dH", y, x);
}

// 화면 중앙 위치 계산
void get_center(int *cols, int *rows) {
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    *cols = w.ws_col;
    *rows = w.ws_row;
}

void draw_box(int width, int height) {
    int cols, rows;
    get_center(&cols, &rows);
    int start_x = (cols - width) / 2;
    int start_y = (rows - height) / 2;

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
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

// --- PAM 관련 함수 (기존과 동일) ---
int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr) {
    char *pass = (char *)appdata_ptr;
    *resp = calloc(num_msg, sizeof(struct pam_response));
    if (*resp == NULL) return PAM_BUF_ERR;
    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            (*resp)[i].resp = strdup(pass);
            (*resp)[i].resp_retcode = 0;
        } else {
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
    if (retval != PAM_SUCCESS) { pam_end(pamh, retval); return 0; }
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) { pam_end(pamh, retval); return 0; }
    retval = pam_open_session(pamh, 0);
    if (retval != PAM_SUCCESS) { pam_end(pamh, retval); return 0; }
    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) { pam_close_session(pamh, 0); pam_end(pamh, retval); return 0; }
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

void launch_session(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) return;
    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
    } else if (pid == 0) {
        char xdg_runtime_dir[64];
        snprintf(xdg_runtime_dir, sizeof(xdg_runtime_dir), "/run/user/%d", pw->pw_uid);
        setenv("USER", pw->pw_name, 1);
        setenv("HOME", pw->pw_dir, 1);
        setenv("SHELL", pw->pw_shell, 1);
        setenv("XDG_RUNTIME_DIR", xdg_runtime_dir, 1);
        setenv("XDG_SESSION_TYPE", "wayland", 1);
        chdir(pw->pw_dir);
        initgroups(username, pw->pw_gid);
        setgid(pw->pw_gid);
        setuid(pw->pw_uid);
        execl(WM_PATH, "niri", NULL);
        exit(1);
    } else {
        wait(NULL);
    }
}

// --- 메인 ---
int main() {
    char username[MAX_LEN];
    char password[MAX_LEN];
    char status_msg[256] = "";
    int msg_type = 0; // 0: normal, 1: success, 2: error

    if (geteuid() != 0) {
        fprintf(stderr, "Please run with sudo.\n");
        return 1;
    }

    while (1) {
        int cols, rows;
        get_center(&cols, &rows);
        int mid_x = cols / 2;
        int mid_y = rows / 2;

        clear_screen();
        draw_box(44, 10);

        // 로고
        move_cursor(mid_x - 4, mid_y - 3);
        printf(COLOR_BOLD COLOR_CYAN "RLOGIND" COLOR_RESET);

        // 상태 메시지 표시
        if (strlen(status_msg) > 0) {
            move_cursor(mid_x - (strlen(status_msg)/2), mid_y - 1);
            if (msg_type == 1) printf(COLOR_GREEN "%s" COLOR_RESET, status_msg);
            else if (msg_type == 2) printf(COLOR_RED "%s" COLOR_RESET, status_msg);
            else printf("%s", status_msg);
            status_msg[0] = 0;
        }

        // 입력 폼
        move_cursor(mid_x - 15, mid_y + 1);
        printf("User: [                ]");
        move_cursor(mid_x - 15, mid_y + 2);
        printf("Pass: [                ]");

        // 사용자 입력
        move_cursor(mid_x - 8, mid_y + 1);
        if (fgets(username, MAX_LEN, stdin) == NULL) break;
        username[strcspn(username, "\n")] = 0;
        if (strlen(username) == 0) continue;

        // 비밀번호 입력
        move_cursor(mid_x - 8, mid_y + 2);
        get_password_input(password, MAX_LEN);

        // 인증 단계
        move_cursor(mid_x - 10, mid_y + 4);
        printf(COLOR_GRAY "Authenticating..." COLOR_RESET);
        fflush(stdout);

        if (authenticate_and_start_pam(username, password)) {
            msg_type = 1;
            sprintf(status_msg, "Welcome, %s!", username);
            launch_session(username);
            close_pam_session();
            msg_type = 0;
            strcpy(status_msg, "Session ended.");
        } else {
            msg_type = 2;
            strcpy(status_msg, "Login Failed");
        }
        
        memset(password, 0, MAX_LEN);
    }
    return 0;
}
