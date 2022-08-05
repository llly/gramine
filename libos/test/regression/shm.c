#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SHMNAME "/shm_test"
#define OPEN_MODE 00666
#define FILE_SIZE 4096*4

const char g_shared_text[] = "test_text";

int main(int argc, const char** argv, const char** envp) {
    pid_t child_pid;

    child_pid = fork();

    if (child_pid == 0) {

        int ret = -1;
        int fd = -1;


        void* add_r = NULL;


        fd = shm_open(SHMNAME, O_RDWR|O_CREAT, OPEN_MODE);
        if(-1 == (ret = fd))
        {
            perror("shm  failed: ");
            return 1;
        }
        ret = ftruncate(fd, FILE_SIZE);
        if(-1 == ret)
        {
            perror("ftruncate faile: ");
            return 1;
        }
        add_r = mmap(NULL, FILE_SIZE, PROT_WRITE, MAP_SHARED, fd, SEEK_SET);
        if(NULL == add_r)
        {
            perror("mmap add_r failed: ");
            return 1;
        }
        printf("addr = %p\n", add_r);

        memcpy(add_r, g_shared_text, sizeof(g_shared_text));

        ret = munmap(add_r, FILE_SIZE);
        if(-1 == ret)
        {
            perror("munmap add_r faile: ");
            return 1;
        }
    } else if (child_pid > 0) {
        /* parent waits for child termination */
        int status;
        pid_t pid = wait(&status);
        if (pid < 0) {
            perror("wait failed");
            return 1;
        }
        if (WIFEXITED(status))
            printf("child exited with status: %d\n", WEXITSTATUS(status));

        int ret = -1;
        int fd = -1;


        void* add_r = NULL;


        //创建或者打开一个共享内存
        fd = shm_open(SHMNAME, O_RDONLY, OPEN_MODE);
        if(-1 == (ret = fd))
        {
            perror("shm_open failed");
            return 1;
        }
        add_r = mmap(NULL, FILE_SIZE, PROT_READ, MAP_SHARED, fd, SEEK_SET);
        if(NULL == add_r)
        {
            perror("mmap add_r failed: ");
            return 1;
        }
        printf("addr = %p\n", add_r);

        if (memcmp(add_r, &g_shared_text, sizeof(g_shared_text))) {
            printf("memcmp failed\n");
            return 1;
        }
        ret = munmap(add_r, FILE_SIZE);
        if(-1 == ret)
        {
            perror("munmap add_r faile: ");
            return 1;
        }
        ret = shm_unlink(SHMNAME);
        if(-1 == ret)
        {
            perror("munmap add_r faile: ");
            return 1;
        }
        puts("TEST OK");
    } else {
        /* error */
        perror("fork failed");
        return 1;
    }

    return 0;
}
