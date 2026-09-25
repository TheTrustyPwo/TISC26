FROM rust:slim-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release && \
    cp target/release/omnitrix /omnitrix.bin

ARG FLAG
RUN printf '%s\n' \
      '#include <unistd.h>' \
      '#include <string.h>' \
      '#include <fcntl.h>' \
      '#define S(x) #x' \
      '#define STR(x) S(x)' \
      '#define W(s) (void)write(1, s, strlen(s))' \
      'int main(void){' \
      '    unsigned char t[16], r[8]; char in[16]; int i, n = 0, k;' \
      '    if (read(open("/dev/urandom", O_RDONLY), r, 8) != 8) return 1;' \
      '    for (i = 0; i < 8; i++) { const char *h = "0123456789abcdef"; t[2*i] = h[r[i]>>4]; t[2*i+1] = h[r[i]&15]; }' \
      '    W("token: "); (void)write(1, t, 16); W("\nsend the same token back: ");' \
      '    alarm(30);' \
      '    while (n < 16 && (k = read(0, in + n, 16 - n)) > 0) n += k;' \
      '    if (n == 16 && !memcmp(in, t, 16)) W(STR(FLAG) "\n");' \
      '    return 0;' \
      '}' \
      > /flag.c \
 && gcc -O2 -static -s -DFLAG="$FLAG" /flag.c -o /flag.bin \
 && chmod 0111 /flag.bin \
 && rm -f /flag.c

FROM scratch

ARG FLAG_FILEPATH

ENV OMNITRIX_BIND=0.0.0.0:7878

COPY --from=builder /lib64/ld-linux-x86-64.so.2 /lib64/
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/

COPY --from=builder /omnitrix.bin /omnitrix
COPY --from=builder /flag.bin $FLAG_FILEPATH

USER 10001:10001

EXPOSE 7878

ENTRYPOINT ["/omnitrix"]
