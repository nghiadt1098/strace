docker rm pwn300 -f && docker build -t pwn300 . &&  docker run -d -t --security-opt=seccomp:unconfined --name pwn300 -p 80:80 pwn300
