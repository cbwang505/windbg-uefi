
EXTERN vtl_call_fn : QWORD
EXTERN vtl_ret_fn : QWORD
EXTERN signalflag : QWORD
EXTERN signalvalue : QWORD
EXTERN synic_message_page_val : QWORD
EXTERN hv_vtl_ap_entry : PROC
EXTERN hv_acquire_hypercall_input_page : PROC
EXTERN hv_acquire_hypercall_output_page : PROC
EXTERN ProcessSynicChannel : PROC
EXTERN dumpbuf : PROC
EXTERN DumpRspFunction : PROC

EXTERN InitGlobalHvVtl1 : PROC
EXTERN HvcallCodeVa : QWORD
EXTERN HvcallCodeVaVTL1 : QWORD
EXTERN SkiInitialMxCsr : DWORD

.CODE








HVHyperCall PROC

 
push rdi
push rdx                                ; Store output PCPU_REG_64

mov rsi, rcx

;
; Hypercall inputs
; RCX = Hypercall input value
; RDX = Input param GPA
; R8  = Output param GPA 
;
mov rcx, qword ptr [rsi+0h]
mov rdx, qword ptr [rsi+8h]
mov r8,  qword ptr [rsi+10h]

    
;
; Extended fast hypercall (set it regardless)
;
EXT_HYPERCALL_XMM_SETUP:
movups xmm0, xmmword ptr[rsi+18h]
movups xmm1, xmmword ptr[rsi+28h]
movups xmm2, xmmword ptr[rsi+38h]
movups xmm3, xmmword ptr[rsi+48h]
movups xmm4, xmmword ptr[rsi+58h]
movups xmm5, xmmword ptr [rsi+68h]
push rsi

MAKE_VMCALL:
;int 3
vmcall

pop rsi
mov     qword ptr [rsi+0h], rdx
mov     qword ptr [rsi+8h], r8
movups  xmmword ptr [rsi+10h], xmm0
movups  xmmword ptr [rsi+20h], xmm1
movups  xmmword ptr [rsi+30h], xmm2
movups  xmmword ptr [rsi+40h], xmm3
movups  xmmword ptr [rsi+50h], xmm4
movups  xmmword ptr [rsi+60h], xmm5

pop rdx
pop rdi
  
;
; RAX from vmcall is return code for our subroutine too
;
ret
HVHyperCall ENDP

HVHyperCallHvCallInstallInterceptAsm PROC
push rdi
push rdx                                ; Store output PCPU_REG_64
push rsi                                ; Store output PCPU_REG_64
sub rsp ,100h

call InitGlobalHvVtl1

call hv_acquire_hypercall_input_page
push rax
call hv_acquire_hypercall_output_page
mov r8,rax
pop rdx
mov rcx,-1
mov qword ptr [rdx+0h],rcx
mov rcx,0b00000002h
mov qword ptr [rdx+8h],rcx
mov rcx,2h
mov qword ptr [rdx+10h],rcx
mov rcx, 004dh
call HvcallCodeVaVTL1
call rax
mov rcx,rax
int 29h

add rsp ,100h
pop rsi
pop rdx
pop rdi
  
;
; RAX from vmcall is return code for our subroutine too
;
ret
HVHyperCallHvCallInstallInterceptAsm ENDP



HVHyperCallHvCallInstallIntercept PROC

 
push rdi
push rdx                                ; Store output PCPU_REG_64
push rsi                                ; Store output PCPU_REG_64

sub rsp ,100h
mov rcx,-1
mov qword ptr [rsp+8h],rcx
mov rcx,0b00000002h
mov qword ptr [rsp+10h],rcx
mov rcx,2h
mov qword ptr [rsp+18h],rcx

mov rsi, rsp

;
; Hypercall inputs
; RCX = Hypercall input value
; RDX = Input param GPA
; R8  = Output param GPA 
;
mov rcx, 01004dh
mov rdx, qword ptr [rsi+8h]
mov r8,  qword ptr [rsi+10h]

    
;
; Extended fast hypercall (set it regardless)
;
EXT_HYPERCALL_XMM_SETUP:
movups xmm0, xmmword ptr[rsi+18h]
movups xmm1, xmmword ptr[rsi+28h]
movups xmm2, xmmword ptr[rsi+38h]
movups xmm3, xmmword ptr[rsi+48h]
movups xmm4, xmmword ptr[rsi+58h]
movups xmm5, xmmword ptr [rsi+68h]

xor rax,rax

MAKE_VMCALL:
;int 3
vmcall

hlt

mov     qword ptr [rsi+0h], rdx
mov     qword ptr [rsi+8h], r8
movups  xmmword ptr [rsi+10h], xmm0
movups  xmmword ptr [rsi+20h], xmm1
movups  xmmword ptr [rsi+30h], xmm2
movups  xmmword ptr [rsi+40h], xmm3
movups  xmmword ptr [rsi+50h], xmm4
movups  xmmword ptr [rsi+60h], xmm5

add rsp ,100h
pop rsi
pop rdx
pop rdi
  
;
; RAX from vmcall is return code for our subroutine too
;
ret
HVHyperCallHvCallInstallIntercept ENDP



MAKE_VMCALL:
;int 3
vmcall
;
; RAX from vmcall is return code for our subroutine too
;
ret

CpuSleep PROC

 hlt

CpuSleep ENDP

CpuNOP PROC
mov rcx ,rax
ret
CpuNOP ENDP

HV_VTL_AP_ENTRY_HANDLER PROC

mov rsp,rbp
xor rcx,rcx
xor rax,rax
ldmxcsr   SkiInitialMxCsr
call HVHyperCallHvCallInstallInterceptAsm
call hv_vtl_ap_entry
mov rcx,1
;call vtl_ret_fn
hlt
jmp CpuSleep
ret

HV_VTL_AP_ENTRY_HANDLER ENDP



ShvlpVtlCall PROC
sub     rsp, 138h
lea     rax, [rsp+100h]
movups  xmmword ptr [rsp+30h], xmm6
movups  xmmword ptr [rsp+40h], xmm7
movups  xmmword ptr [rsp+50h], xmm8
movups  xmmword ptr [rsp+60h], xmm9
movups  xmmword ptr [rsp+70h], xmm10
movups  xmmword ptr [rax-80h], xmm11
movups  xmmword ptr [rax-70h], xmm12
movups  xmmword ptr [rax-60h], xmm13
movups  xmmword ptr [rax-50h], xmm14
movups  xmmword ptr [rax-40h], xmm15
mov     [rax-8], rbp
mov     [rax], rbx
mov     [rax+8], rdi
mov     [rax+10h], rsi
mov     [rax+18h], r12
mov     [rax+20h], r13
mov     [rax+28h], r14
mov     [rax+30h], r15
mov     rax, vtl_call_fn
xor     ecx, ecx
call    rax ; ShvlpVtlCall
mov rcx ,rax
hlt
jmp CpuSleep
lea     rcx, [rsp+100h]
movups  xmm6, xmmword ptr [rsp+30h]
movups  xmm7, xmmword ptr [rsp+40h]
movups  xmm8, xmmword ptr [rsp+50h]
movups  xmm9, xmmword ptr [rsp+60h]
movups  xmm10, xmmword ptr [rsp+70h]
movups  xmm11, xmmword ptr [rcx-80h]
movups  xmm12, xmmword ptr [rcx-70h]
movups  xmm13, xmmword ptr [rcx-60h]
movups  xmm14, xmmword ptr [rcx-50h]
movups  xmm15, xmmword ptr [rcx-40h]
mov     rbx, [rcx]
mov     rdi, [rcx+8]
mov     rsi, [rcx+10h]
mov     r12, [rcx+18h]
mov     r13, [rcx+20h]
mov     r14, [rcx+28h]
mov     r15, [rcx+30h]
mov     rbp, [rcx-8]
add     rsp, 138h
ret
ShvlpVtlCall ENDP




hdlmsgint PROC
mov signalflag,1

sub     rsp, 32 + 8   
call ProcessSynicChannel
add     rsp, 32 + 8    

IRETQ 
hdlmsgint ENDP




EnableInterrupts PROC
sti
ret
EnableInterrupts ENDP

DisableInterrupts PROC
cli
ret
DisableInterrupts ENDP

DumpRsp PROC
mov rcx,rsp
sub     rsp, 32 + 8
call DumpRspFunction
add     rsp, 32 + 8  
ret
DumpRsp ENDP
END


