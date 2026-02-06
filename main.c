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

#define MAX_LEN 100
#define WM_PATH "/usr/bin/niri" // 실행할 윈도우 매니저 경로

// PAM 핸들러 전역 변수 (세션 종료를 위해 필요)
pam_handle_t *pamh = NULL;

// --- 화면 유틸리티 ---
void clear_screen() {
    printf("\033[H\033[J");
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
    printf("\n");
}

// --- PAM 관련 함수 ---
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

    // 1. PAM 시작
    retval = pam_start("login", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) return 0;

    // 2. 인증 (Authenticate)
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return 0;
    }

    // 3. 계정 상태 확인 (Account Management)
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return 0;
    }

    // 4. 세션 열기 (Open Session) - 매우 중요!
    // 이것이 있어야 /run/user/UID가 생성되고 하드웨어 접근 권한이 부여됨
    retval = pam_open_session(pamh, 0);
    if (retval != PAM_SUCCESS) {
        fprintf(stderr, "PAM session open failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return 0;
    }
    
    // 5. 자격 증명 설정 (Set Credentials) - 그룹 멤버십 등 초기화
    retval = pam_setcred(pamh, PAM_ESTABLISH_CRED);
    if (retval != PAM_SUCCESS) {
        pam_close_session(pamh, 0);
        pam_end(pamh, retval);
        return 0;
    }

    return 1; // 모든 단계 성공
}

void close_pam_session() {
    if (pamh) {
        pam_setcred(pamh, PAM_DELETE_CRED);
        pam_close_session(pamh, 0);
        pam_end(pamh, PAM_SUCCESS);
        pamh = NULL;
    }
}

// --- 세션 실행 (Niri 실행) ---
void launch_session(const char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) return;

    pid_t pid = fork();

    if (pid == -1) {
        perror("Fork failed");
    } else if (pid == 0) {
        // [자식 프로세스]
        
        // 1. Wayland 필수 환경 변수 설정 (XDG_RUNTIME_DIR)
        char xdg_runtime_dir[64];
        snprintf(xdg_runtime_dir, sizeof(xdg_runtime_dir), "/run/user/%d", pw->pw_uid);
        
        // 환경 변수 설정 (기존 환경 유지 + 덮어쓰기)
        setenv("USER", pw->pw_name, 1);
        setenv("HOME", pw->pw_dir, 1);
        setenv("SHELL", pw->pw_shell, 1);
        setenv("XDG_RUNTIME_DIR", xdg_runtime_dir, 1);
        setenv("XDG_SESSION_TYPE", "wayland", 1); // Wayland 명시

        // 2. 홈 디렉토리로 이동
        chdir(pw->pw_dir);

        // 3. 권한 낮추기 (Root -> User)
        initgroups(username, pw->pw_gid);
        setgid(pw->pw_gid);
        setuid(pw->pw_uid);

        printf("Launching for %s...\n", username);
        
        // 4. Window Manager 실행
        // execl의 첫 번째 인자는 경로, 두 번째는 프로세스 이름(argv[0]), 마지막은 NULL
        execl(WM_PATH, "niri", "", NULL);
        
        // 실행 실패 시
        perror("Failed to launch window manager");
        exit(1);
    } else {
        // [부모 프로세스]
        // 자식 프로세스(Niri)가 종료될 때까지 대기
        wait(NULL);
    }
}

// --- 메인 ---
int main() {
    char username[MAX_LEN];
    char password[MAX_LEN];
    char message[256] = "";

    if (geteuid() != 0) {
        fprintf(stderr, "Run with sudo.\n");
        return 1;
    }

    while (1) {
        clear_screen();
        // 간단한 로고
        printf("\n  [ rlogind ]\n\n");
        
        if (strlen(message) > 0) {
            printf("  > %s\n\n", message);
            message[0] = 0;
        }

        printf("  User: ");
        if (fgets(username, MAX_LEN, stdin) == NULL) break;
        username[strcspn(username, "\n")] = 0;
        if (strlen(username) == 0) continue;

        printf("  Pass: ");
        get_password_input(password, MAX_LEN);

        // PAM 인증 및 세션 시작
        if (authenticate_and_start_pam(username, password)) {
            sprintf(message, "Session started for %s.", username);
            
            // Niri 실행
            launch_session(username);
            
            // Niri 종료 후 PAM 세션 정리
            close_pam_session();
            strcpy(message, "Session ended.");
        } else {
            strcpy(message, "Login failed.");
        }
        
        memset(password, 0, MAX_LEN);
    }
    return 0;
}
