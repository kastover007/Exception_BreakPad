#include <QCoreApplication>
#include <qt_windows.h>
#include <DbgHelp.h>
#include <QStandardPaths>
#include <QDir>
#include <QDateTime>
#include <QString>
#include <QDebug>
#include <QTextCodec>

//#ifdef Q_OS_WIN
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI MyDummySetUnhandledExceptionFilter(
        LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
    return nullptr;
}

BOOL PreventSetUnhandledExceptionFilter()
{
    HMODULE hKernel32 = ::LoadLibraryW(L"kernel32.dll");
    if (hKernel32 == nullptr)
        return false;
    void *pOrgEntry = GetProcAddress(hKernel32, "SetUnhandledExceptionFilter");
    if (pOrgEntry == nullptr)
        return false;

#ifdef _M_IX86
    // Code for x86:
    // 33 C0                xor         eax,eax
    // C2 04 00             ret         4
    unsigned char szExecute[] = { 0x33, 0xC0, 0xC2, 0x04, 0x00 };
#elif _M_X64
    // 33 C0                xor         eax,eax
    // C3                   ret
    unsigned char szExecute[] = { 0x33, 0xC0, 0xC3 };
#else
#error "The following code only works for x86 and x64!"
#endif

    SIZE_T bytesWritten = 0;
    bool bRet = WriteProcessMemory(GetCurrentProcess(),
                                   pOrgEntry, szExecute, sizeof(szExecute), &bytesWritten);
    return bRet;
}

long /*__stdcall*/ callback(EXCEPTION_POINTERS* pException)
{
    // 在程序exe的上级目录中创建dmp文件夹
    QDir *dmp = new QDir;
    bool exist = dmp->exists("../dmp/");
    if(exist == false)
    {
        dmp->mkdir("../dmp/");
    }
    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy_MM_dd_hh_mm_ss");
    QString time =  current_date + ".dmp";
    EXCEPTION_RECORD *record = pException->ExceptionRecord;
    QString errCode(QString::number(record->ExceptionCode, 16));
    QString errAddr(QString::number((uint)record->ExceptionAddress, 16));
    QString errFlag(QString::number(record->ExceptionFlags, 16));
    QString errPara(QString::number(record->NumberParameters, 16));
    qDebug()<<"errCode: "<<errCode;
    qDebug()<<"errAddr: "<<errAddr;
    qDebug()<<"errFlag: "<<errFlag;
    qDebug()<<"errPara: "<<errPara;
    HANDLE hDumpFile = CreateFile((LPCWSTR)QString("../dmp/" + time).utf16(),
                                  GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hDumpFile != INVALID_HANDLE_VALUE)
    {
        qDebug() <<QString("../dmp/" + time);
        MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
        dumpInfo.ExceptionPointers = pException;
        dumpInfo.ThreadId = GetCurrentThreadId();
        dumpInfo.ClientPointers = TRUE;
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),hDumpFile, MiniDumpNormal, &dumpInfo, nullptr, nullptr);
        CloseHandle(hDumpFile);
    }
    else{
        qDebug()<<"hDumpFile == null";
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

#define QBREAKPAD_VERSION  0x000400

#if defined(Q_OS_MAC)
#include "client/mac/handler/exception_handler.h"
#elif defined(Q_OS_LINUX)
#include "client/linux/handler/exception_handler.h"
#elif defined(Q_OS_WIN32)
#include "client/windows/handler/exception_handler.h"
#endif

#if defined(Q_OS_WIN32)
bool DumpCallback(const wchar_t* dump_dir,
                                    const wchar_t* minidump_id,
                                    void* context,
                                    EXCEPTION_POINTERS* exinfo,
                                    MDRawAssertionInfo* assertion,
                                    bool succeeded)
#elif defined(Q_OS_MAC)
bool DumpCallback(const char *dump_dir,
                                    const char *minidump_id,
                                    void *context, bool succeeded)
#else
bool DumpCallback(const google_breakpad::MinidumpDescriptor& descriptor,
                                    void* context,
                                    bool succeeded)
#endif
{
#ifdef Q_OS_LINUX
    Q_UNUSED(descriptor);
#endif
    Q_UNUSED(context);
#if defined(Q_OS_WIN32)
    Q_UNUSED(assertion);
    Q_UNUSED(exinfo);
#endif
    /*
        NO STACK USE, NO HEAP USE THERE !!!
        Creating QString's, using qDebug, etc. - everything is crash-unfriendly.
    */

#if defined(Q_OS_WIN32)
    QString path = QString::fromWCharArray(dump_dir) + QLatin1String("/") + QString::fromWCharArray(minidump_id);
    qDebug("%s, dump path: %s\n", succeeded ? "Succeed to write minidump" : "Failed to write minidump", qPrintable(path));
#elif defined(Q_OS_MAC)
    QString path = QString::fromUtf8(dump_dir) + QLatin1String("/") + QString::fromUtf8(minidump_id);
    qDebug("%s, dump path: %s\n", succeeded ? "Succeed to write minidump" : "Failed to write minidump", qPrintable(path));
#else
    qDebug("%s, dump path: %s\n", succeeded ? "Succeed to write minidump" : "Failed to write minidump", descriptor.path());
#endif

    return succeeded;
}
void setDumpPath(const QString& path)
{
    QString absPath = path;
    if(!QDir::isAbsolutePath(absPath)) {
        absPath = QDir::cleanPath(qApp->applicationDirPath() + "/" + path);
    }
    Q_ASSERT(QDir::isAbsolutePath(absPath));

    QDir().mkpath(absPath);
    if (!QDir().exists(absPath)) {
        qDebug("Failed to set dump path which not exists: %s", qPrintable(absPath));
        return;
    }

//    d->dumpPath = absPath;

// NOTE: ExceptionHandler initialization
    google_breakpad::ExceptionHandler* pExptHandler;
#if defined(Q_OS_WIN32)
    pExptHandler = new google_breakpad::ExceptionHandler(absPath.toStdWString(), /*FilterCallback*/ 0,
                                                        DumpCallback, /*context*/ 0,
                                                        google_breakpad::ExceptionHandler::HANDLER_ALL);
#elif defined(Q_OS_MAC)
    pExptHandler = new google_breakpad::ExceptionHandler(absPath.toStdString(),
                                                            /*FilterCallback*/ 0,
                                                        DumpCallback, /*context*/ 0, true, NULL);
#else
    pExptHandler = new google_breakpad::ExceptionHandler(google_breakpad::MinidumpDescriptor(absPath.toStdString()),
                                                            /*FilterCallback*/ 0,
                                                            DumpCallback,
                                                            /*context*/ 0,
                                                            true,
                                                            -1);
#endif
}

//#endif
int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QTextCodec *codec = QTextCodec::codecForLocale();
    QTextCodec::setCodecForLocale(QTextCodec::codecForLocale());

    {
        //#ifdef Q_OS_WIN
    //    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)callback);
        //禁用SetUnhandledExceptionFilter,防止异常回调函数被覆盖.
    //    BOOL bRet = PreventSetUnhandledExceptionFilter();
    }

    {
        QDir *dmp = new QDir;
        bool exist = dmp->exists("../dmp/");
        if(exist == false)
        {
            dmp->mkdir("../dmp/");
        }

        setDumpPath(QString("../dmp/"));
    }


    //test crash
    QString *pNew = new QString(1);
    delete  pNew;
    pNew->append(2);

    return a.exec();
}
