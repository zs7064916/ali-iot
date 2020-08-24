/**
 * NOTE:
 *
 * HAL_TCP_xxx API reference implementation: wrappers/os/ubuntu/HAL_TCP_linux.c
 *
 * *** Ported by guanwei ***
 *
 */
#include "infra_types.h"
#include "infra_defs.h"
#include "infra_compat.h"
#include "wrappers_defs.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>

#include "bsj_trace.h"
#include "bsj_thread.h"
#include "bsj_socket_ex.h"
#include "infra_config.h"

#include "feitian_log.h"

#ifdef SUPPORT_TLS
#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/certs.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"
#endif

#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL 2
#endif

#if 1
static char _product_key[IOTX_PRODUCT_KEY_LEN + 1]       = "a1rhfJArIBz";        
static char _product_secret[IOTX_PRODUCT_SECRET_LEN + 1] = "OrX4pHX4f1ir8skP";  
static char _device_name[IOTX_DEVICE_NAME_LEN + 1]       = "W9VYrLEu45dAlNGy4ANF";        
static char _device_secret[IOTX_DEVICE_SECRET_LEN + 1]   = "DILmzAcht4g8W3RomQHYlaDzEoBbduov";

#else

static char _product_key[IOTX_PRODUCT_KEY_LEN + 1]       = "a1wUL0CkRge";        
static char _product_secret[IOTX_PRODUCT_SECRET_LEN + 1] = "EN2vF2shuEGnhGis";        
static char _device_name[IOTX_DEVICE_NAME_LEN + 1]       = "BC82_Demo";        
static char _device_secret[IOTX_DEVICE_SECRET_LEN + 1]   = "HdFdTrqSyX21eqjKrJrEaPFyXLDAXrTr";
#endif

/**
?*
?* 函数 HAL_Free() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_Free() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_Free(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_Free, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Deallocate memory block
 *
 * @param[in] ptr @n Pointer to a memory block previously allocated with platform_malloc.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_Free(void *ptr)
{
    free(ptr);
	return;
}

int HAL_SetProductKey(char *product_key) 
{    
    int len = strlen(product_key);   
    
    if (len > IOTX_PRODUCT_KEY_LEN) {
        return -1;
    }    
    memset(_product_key, 0x0, IOTX_PRODUCT_KEY_LEN + 1);    
    strncpy(_product_key, product_key, len);    
    return len;
}

int HAL_SetDeviceName(char *device_name)
{    
    int len = strlen(device_name); 
    
    if (len > IOTX_DEVICE_NAME_LEN) {        
        return -1;    
    }    
    memset(_device_name, 0x0, IOTX_DEVICE_NAME_LEN + 1);    
    strncpy(_device_name, device_name, len);    
    return len;
}

int HAL_SetProductSecret(char *product_secret)
{    
    int len = strlen(product_secret);   
    
    if (len > IOTX_PRODUCT_SECRET_LEN) {        
        return -1;    
    }    
    memset(_product_secret, 0x0, IOTX_PRODUCT_SECRET_LEN + 1);    
    strncpy(_product_secret, product_secret, len);    
    return len;
}

int HAL_SetDeviceSecret(char *device_secret)
{    
    int len = strlen(device_secret);    
    if (len > IOTX_DEVICE_SECRET_LEN) {
        return -1;    
    }    
    memset(_device_secret, 0x0, IOTX_DEVICE_SECRET_LEN + 1);    
    strncpy(_device_secret, device_secret, len);    
    return len;
}

/**
?*
?* 函数 HAL_GetDeviceName() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_GetDeviceName() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_GetDeviceName(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_GetDeviceName, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Get device name from user's system persistent storage
 *
 * @param [ou] device_name: array to store device name, max length is IOTX_DEVICE_NAME_LEN
 * @return the actual length of device name
 */
int HAL_GetDeviceName(char device_name[IOTX_DEVICE_NAME_LEN + 1])
{
    int len = strlen(_device_name);
    memset(device_name, 0x0, IOTX_DEVICE_NAME_LEN + 1);

    strncpy(device_name, _device_name, len);

    return strlen(device_name);
}


/**
?*
?* 函数 HAL_GetDeviceSecret() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_GetDeviceSecret() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_GetDeviceSecret(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_GetDeviceSecret, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Get device secret from user's system persistent storage
 *
 * @param [ou] device_secret: array to store device secret, max length is IOTX_DEVICE_SECRET_LEN
 * @return the actual length of device secret
 */
int HAL_GetDeviceSecret(char device_secret[IOTX_DEVICE_SECRET_LEN + 1])
{
    int len = strlen(_device_secret);
    memset(device_secret, 0x0, IOTX_DEVICE_SECRET_LEN + 1);

    strncpy(device_secret, _device_secret, len);

    return len;
}


/**
?*
?* 函数 HAL_GetFirmwareVersion() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_GetFirmwareVersion() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_GetFirmwareVersion(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_GetFirmwareVersion, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Get firmware version
 *
 * @param [ou] version: array to store firmware version, max length is IOTX_FIRMWARE_VER_LEN
 * @return the actual length of firmware version
 */
int HAL_GetFirmwareVersion(char *version)
{
    char *ver = "app-1.0.0-20190813.1000";
    int len = strlen(ver);
    memset(version, 0x0, IOTX_FIRMWARE_VER_LEN);
    strncpy(version, ver, IOTX_FIRMWARE_VER_LEN);
    version[len] = '\0';
    return strlen(version);
}


/**
?*
?* 函数 HAL_GetProductKey() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_GetProductKey() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_GetProductKey(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_GetProductKey, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Get product key from user's system persistent storage
 *
 * @param [ou] product_key: array to store product key, max length is IOTX_PRODUCT_KEY_LEN
 * @return  the actual length of product key
 */
int HAL_GetProductKey(char product_key[IOTX_PRODUCT_KEY_LEN + 1])
{
    int len = strlen(_product_key);
    memset(product_key, 0x0, IOTX_PRODUCT_KEY_LEN + 1);

    strncpy(product_key, _product_key, len);

    return len;
}

/* added by guanwei */
int HAL_GetProductSecret(char product_secret[IOTX_PRODUCT_SECRET_LEN + 1])
{
    int len = strlen(_product_secret);
    memset(product_secret, 0x0, IOTX_PRODUCT_SECRET_LEN + 1);

    strncpy(product_secret, _product_secret, len);

    return len;
}
/* end by guanwei */

/**
?*
?* 函数 HAL_Malloc() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_Malloc() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_Malloc(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_Malloc, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Allocates a block of size bytes of memory, returning a pointer to the beginning of the block.
 *
 * @param [in] size @n specify block size in bytes.
 * @return A pointer to the beginning of the block.
 * @see None.
 * @note Block value is indeterminate.
 */
void *HAL_Malloc(uint32_t size)
{
	return malloc(size);
}


/**
?*
?* 函数 HAL_MutexCreate() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_MutexCreate() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_MutexCreate(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_MutexCreate, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Create a mutex.
 *
 * @retval NULL : Initialize mutex failed.
 * @retval NOT_NULL : The mutex handle.
 * @see None.
 * @note None.
 */
void *HAL_MutexCreate(void)
{
    BSJ_Mutex_t *mutex;
    mutex = BSJ_MutexCreate();
    
	return (void *)mutex;
}


/**
?*
?* 函数 HAL_MutexDestroy() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_MutexDestroy() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_MutexDestroy(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_MutexDestroy, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Destroy the specified mutex object, it will release related resource.
 *
 * @param [in] mutex @n The specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexDestroy(void *mutex)
{
    BSJ_MutexDelete((BSJ_Mutex_t *)mutex);
}


/**
?*
?* 函数 HAL_MutexLock() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_MutexLock() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_MutexLock(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_MutexLock, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Waits until the specified mutex is in the signaled state.
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexLock(void *mutex)
{
    BSJ_MutexLock((BSJ_Mutex_t *)mutex, 0);
}


/**
?*
?* 函数 HAL_MutexUnlock() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_MutexUnlock() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_MutexUnlock(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_MutexUnlock, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Releases ownership of the specified mutex object..
 *
 * @param [in] mutex @n the specified mutex.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_MutexUnlock(void *mutex)
{
    BSJ_MutexUnlock((BSJ_Mutex_t *)mutex);
}


/**
?*
?* 函数 HAL_Printf() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_Printf() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_Printf(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_Printf, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Writes formatted data to stream.
 *
 * @param [in] fmt: @n String that contains the text to be written, it can optionally contain embedded format specifiers
     that specifies how subsequent arguments are converted for output.
 * @param [in] ...: @n the variable argument list, for formatted and inserted in the resulting string replacing their respective specifiers.
 * @return None.
 * @see None.
 * @note None.
 */

#define LOG_TAG_IOTKIT OSI_MAKE_LOG_TAG('I', 'O', 'T', 'K')
void HAL_Printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    osiTraceVprintf(LOG_TAG_IOTKIT, fmt, args);
    va_end(args);
}

/**
?*
?* 函数 HAL_SleepMs() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_SleepMs() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_SleepMs(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_SleepMs, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Sleep thread itself.
 *
 * @param [in] ms @n the time interval for which execution is to be suspended, in milliseconds.
 * @return None.
 * @see None.
 * @note None.
 */
void HAL_SleepMs(uint32_t ms)
{
    BSJ_ThreadSleep(ms);
	return;
}


/**
?*
?* 函数 HAL_Snprintf() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_Snprintf() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_Snprintf(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_Snprintf, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Writes formatted data to string.
 *
 * @param [out] str: @n String that holds written text.
 * @param [in] len: @n Maximum length of character will be written
 * @param [in] fmt: @n Format that contains the text to be written, it can optionally contain embedded format specifiers
     that specifies how subsequent arguments are converted for output.
 * @param [in] ...: @n the variable argument list, for formatted and inserted in the resulting string replacing their respective specifiers.
 * @return bytes of character successfully written into string.
 * @see None.
 * @note None.
 */
int HAL_Snprintf(char *str, const int len, const char *fmt, ...)
{
    va_list args;
    int     rc;

    va_start(args, fmt);
    rc = vsnprintf(str, len, fmt, args);
    va_end(args);
    
	return rc;
}


int HAL_Vsnprintf(char *str, const int len, const char *format, va_list ap)
{
    return vsnprintf(str, len, format, ap);
}



/**
?*
?* 函数 HAL_UptimeMs() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_UptimeMs() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_UptimeMs(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_UptimeMs, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/os/ubuntu/HAL_OS_linux.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
/**
 * @brief Retrieves the number of milliseconds that have elapsed since the system was boot.
 *
 * @return the number of milliseconds.
 * @see None.
 * @note None.
 */
uint64_t HAL_UptimeMs(void)
{
    struct timeval now;
	gettimeofday(&now, NULL);
	
	return (uint64_t)(now.tv_sec * 1000 + now.tv_usec / 1000);
}


/**
?*
?* 函数 HAL_SSL_Destroy() 需要SDK的使用者针对SDK将运行的硬件平台填充实现, 供SDK调用
?* ---
?* Interface of HAL_SSL_Destroy() requires to be implemented by user of SDK, according to target device platform
?*
?* 如果需要参考如何实现函数 HAL_SSL_Destroy(), 可以查阅SDK移植到 Ubuntu Linux 上时的示例代码
?* ---
?* If you need guidance about how to implement HAL_SSL_Destroy, you can check its reference implementation for Ubuntu platform
?*
?* https://code.aliyun.com/linkkit/c-sdk/blob/v3.0.1/wrappers/tls/HAL_TLS_mbedtls.c
?*
?*
?* 注意! HAL_XXX() 系列的函数虽然有阿里提供的对应参考实现, 但不建议您不做任何修改/检视的应用于您的商用设备!
?*?
?* 注意! 参考示例实现仅用于解释各个 HAL_XXX() 系列函数的语义!
?*?
?*/
#ifdef SUPPORT_TLS

#define SEND_TIMEOUT_SECONDS                (10)
#define GUIDER_ONLINE_HOSTNAME              ("iot-auth.cn-shanghai.aliyuncs.com")
#define GUIDER_PRE_ADDRESS                  ("100.67.80.107")
#define BSJ_SSL

#ifndef CONFIG_MBEDTLS_DEBUG_LEVEL
    #define CONFIG_MBEDTLS_DEBUG_LEVEL 0
#endif

typedef struct {
    mbedtls_ssl_context ssl_ctx;        /* mbedtls ssl context */
    mbedtls_net_context net_ctx;        /* Fill in socket id */
    mbedtls_ssl_config ssl_conf;        /* SSL configuration */
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt_profile profile;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
    mbedtls_timing_delay_context timer;
} IotTlsDataParams_t, *IotTlsDataParams_pt;



void *HAL_Malloc(uint32_t size);
void HAL_Free(void *ptr);

static unsigned int mbedtls_mem_used = 0;
static unsigned int mbedtls_max_mem_used = 0;
static ssl_hooks_t g_ssl_hooks = {HAL_Malloc, HAL_Free};


#define MBEDTLS_MEM_INFO_MAGIC   0x12345678

typedef struct {
    int magic;
    int size;
} mbedtls_mem_info_t;

#if defined(TLS_SAVE_TICKET)

#define TLS_MAX_SESSION_BUF 384
#define KV_SESSION_KEY  "TLS_SESSION"

extern int HAL_Kv_Set(const char *key, const void *val, int len, int sync);

extern int HAL_Kv_Get(const char *key, void *val, int *buffer_len);

static mbedtls_ssl_session *saved_session = NULL;

static int ssl_serialize_session(const mbedtls_ssl_session *session,
                                 unsigned char *buf, size_t buf_len,
                                 size_t *olen)
{
    unsigned char *p = buf;
    size_t left = buf_len;

    if (left < sizeof(mbedtls_ssl_session)) {
        return (MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
    }

    memcpy(p, session, sizeof(mbedtls_ssl_session));
    p += sizeof(mbedtls_ssl_session);
    left -= sizeof(mbedtls_ssl_session);
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    if (left < sizeof(mbedtls_ssl_session)) {
        return (MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL);
    }
    memcpy(p, session->ticket, session->ticket_len);
    p += session->ticket_len;
    left -= session->ticket_len;
#endif

    *olen = p - buf;

    return (0);
}

static int ssl_deserialize_session(mbedtls_ssl_session *session,
                                   const unsigned char *buf, size_t len)
{
    const unsigned char *p = buf;
    const unsigned char *const end = buf + len;

    if (sizeof(mbedtls_ssl_session) > (size_t)(end - p)) {
        return (MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }

    memcpy(session, p, sizeof(mbedtls_ssl_session));
    p += sizeof(mbedtls_ssl_session);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    session->peer_cert = NULL;
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    if (session->ticket_len > 0) {
        if (session->ticket_len > (size_t)(end - p)) {
            return (MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
        }
        session->ticket = HAL_Malloc(session->ticket_len);
        if (session->ticket == NULL) {
            return (MBEDTLS_ERR_SSL_ALLOC_FAILED);
        }
        memcpy(session->ticket, p, session->ticket_len);
        p += session->ticket_len;
        feitian_log(LOG_DEBUG, "saved ticket len = %d \r\n", (int)session->ticket_len);
    }
#endif

    if (p != end) {
        return (MBEDTLS_ERR_SSL_BAD_INPUT_DATA);
    }

    return (0);
}
#endif

static void _ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    #if 1
    ((void) level);
    if (NULL != ctx) {
#if 0
        fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
        fflush((FILE *) ctx);
#endif
        feitian_log(LOG_DEBUG, "_ssl_debug %s\n", str);
    }
    #endif
}

static int _real_confirm(int verify_result)
{
    feitian_log(LOG_DEBUG, "certificate verification result: 0x%02x\n", verify_result);

#if defined(FORCE_SSL_VERIFY)
    if ((verify_result & MBEDTLS_X509_BADCERT_EXPIRED) != 0) {
        feitian_log(LOG_DEBUG, "! fail ! ERROR_CERTIFICATE_EXPIRED\n");
        return -1;
    }

    if ((verify_result & MBEDTLS_X509_BADCERT_REVOKED) != 0) {
        feitian_log(LOG_DEBUG, "! fail ! server certificate has been revoked\n");
        return -1;
    }

    if ((verify_result & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0) {
        feitian_log(LOG_DEBUG, "! fail ! CN mismatch\n");
        return -1;
    }

    if ((verify_result & MBEDTLS_X509_BADCERT_NOT_TRUSTED) != 0) {
        feitian_log(LOG_DEBUG, "! fail ! self-signed or not signed by a trusted CA\n");
        return -1;
    }
#endif

    return 0;
}

#if defined(_PLATFORM_IS_LINUX_)
static int net_prepare(void)
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
   !defined(EFI32)
    WSADATA wsaData;
    static int wsa_init_done = 0;

    if (wsa_init_done == 0) {
        if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
            return (MBEDTLS_ERR_NET_SOCKET_FAILED);
        }

        wsa_init_done = 1;
    }
#else
#if !defined(EFIX64) && !defined(EFI32)
    signal(SIGPIPE, SIG_IGN);
#endif
#endif
    return (0);
}


static int mbedtls_net_connect_timeout(mbedtls_net_context *ctx, const char *host,
                                       const char *port, int proto, unsigned int timeout)
{
    int ret;
    struct addrinfo hints, *addr_list, *cur;
    struct timeval sendtimeout;
    uint8_t dns_retry = 0;

    if ((ret = net_prepare()) != 0) {
        return (ret);
    }

    /* Do name resolution with both IPv6 and IPv4 */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    while(dns_retry++ < 8) {
        ret = getaddrinfo(host, port, &hints, &addr_list);
        if (ret != 0) {
            feitian_log(LOG_DEBUG, "getaddrinfo error[%d], res: %s, host: %s, port: %s\n", dns_retry, gai_strerror(ret), host, port);
            sleep(1);
            continue;
        }else{
            break;
        }
    }

    if (ret != 0) {
        return (MBEDTLS_ERR_NET_UNKNOWN_HOST);
    }

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
        char ip4_str[INET_ADDRSTRLEN];

        ctx->fd = (int) socket(cur->ai_family, cur->ai_socktype,
                               cur->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        sendtimeout.tv_sec = timeout;
        sendtimeout.tv_usec = 0;

        if (0 != setsockopt(ctx->fd, SOL_SOCKET, SO_SNDTIMEO, &sendtimeout, sizeof(sendtimeout))) {
            feitian_log(LOG_DEBUG, "setsockopt");
            feitian_log(LOG_DEBUG, "setsockopt error\n");
        }
        feitian_log(LOG_DEBUG, "setsockopt SO_SNDTIMEO timeout: %ds\n", (int)sendtimeout.tv_sec);

        inet_ntop(AF_INET, &((const struct sockaddr_in *)cur->ai_addr)->sin_addr, ip4_str, INET_ADDRSTRLEN);
        feitian_log(LOG_DEBUG, "connecting IP_ADDRESS: %s\n", ip4_str);

        if (connect(ctx->fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            ret = 0;
            break;
        }

        close(ctx->fd);
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }

    freeaddrinfo(addr_list);

    return (ret);
}
#endif

void *_SSLCalloc_wrapper(size_t n, size_t size)
{
    unsigned char *buf = NULL;
    mbedtls_mem_info_t *mem_info = NULL;

    if (n == 0 || size == 0) {
        return NULL;
    }

    buf = (unsigned char *)(g_ssl_hooks.malloc(n * size + sizeof(mbedtls_mem_info_t)));
    if (NULL == buf) {
        return NULL;
    } else {
        memset(buf, 0, n * size + sizeof(mbedtls_mem_info_t));
    }

    mem_info = (mbedtls_mem_info_t *)buf;
    mem_info->magic = MBEDTLS_MEM_INFO_MAGIC;
    mem_info->size = n * size;
    buf += sizeof(mbedtls_mem_info_t);

    mbedtls_mem_used += mem_info->size;
    if (mbedtls_mem_used > mbedtls_max_mem_used) {
        mbedtls_max_mem_used = mbedtls_mem_used;
    }

    /* BSJ_LOG("INFO -- mbedtls malloc: %p %d  total used: %d  max used: %d\r\n",
                       buf, (int)size, mbedtls_mem_used, mbedtls_max_mem_used); */

    return buf;
}

void _SSLFree_wrapper(void *ptr)
{
    mbedtls_mem_info_t *mem_info = NULL;
    if (NULL == ptr) {
        return;
    }

    mem_info = (mbedtls_mem_info_t *)((unsigned char *)ptr - sizeof(mbedtls_mem_info_t));
    if (mem_info->magic != MBEDTLS_MEM_INFO_MAGIC) {
        BSJ_LOG("Warning - invalid mem info magic: 0x%x\r\n", mem_info->magic);
    }

    mbedtls_mem_used -= mem_info->size;
    /* BSJ_LOG("INFO mbedtls free: %p %d  total used: %d  max used: %d\r\n",
                       ptr, mem_info->size, mbedtls_mem_used, mbedtls_max_mem_used);*/

    g_ssl_hooks.free(mem_info);
}

#if 1
int HAL_SSL_Read(uintptr_t handle, char *buf, int len, int timeout_ms)
{
    uint32_t        readLen = 0;
    static int      net_status = 0;
    int             ret = -1;
    //char            err_str[33];
    IotTlsDataParams_t *ssl = (IotTlsDataParams_t *)handle;

    /*
     * the max of fragmentation of itls is 2048
     * if len > 2048, needs to read more times, so we set max time for timeout is 10s.
     */
    if (len > 2048 && timeout_ms < 10000)
        timeout_ms = 10000;
    //feitian_log(LOG_DEBUG, "timeout_ms:%d",timeout_ms);
    mbedtls_ssl_conf_read_timeout(&(ssl->ssl_conf), timeout_ms);
    while (readLen < len) {
        ret = mbedtls_ssl_read(&(ssl->ssl_ctx), (unsigned char *)(buf + readLen), (len - readLen));
        if (ret > 0) {
            readLen += ret;
            net_status = 0;
        } else if (ret == 0) {
            /* if ret is 0 and net_status is -2, indicate the connection is closed during last call */
            return (net_status == -2) ? net_status : readLen;
        } else {
            if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ret) {
                feitian_log(LOG_DEBUG, "ssl recv peer close notify");
                net_status = -2; /* connection is closed */
                break;
            } else if ((MBEDTLS_ERR_SSL_TIMEOUT == ret)
                       || (MBEDTLS_ERR_SSL_CONN_EOF == ret)
                       || (MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED == ret)
                       || (MBEDTLS_ERR_SSL_NON_FATAL == ret)) {
                /* read already complete */
                /* if call mbedtls_ssl_read again, it will return 0 (means EOF) */

                return readLen;
            } else {
                feitian_log(LOG_DEBUG, "ssl recv error: code = %d", ret);
                net_status = -1;
                return -1; /* Connection error */
            }
        }
    }

    return (readLen > 0) ? readLen : net_status;
}

int HAL_SSL_Write(uintptr_t handle, const char *buf, int len, int timeout_ms)
{
    uint32_t writtenLen = 0;
    int ret = -1;
    IotTlsDataParams_t *ssl = (IotTlsDataParams_t *)handle;

    if (ssl == NULL) {
        return -1;
    }
    while (writtenLen < len) {
        ret = mbedtls_ssl_write(&(ssl->ssl_ctx), (unsigned char *)(buf + writtenLen), (len - writtenLen));
        if (ret > 0) {
            writtenLen += ret;
            continue;
        } else if (ret == 0) {
            feitian_log(LOG_DEBUG, "ssl write timeout");
            return 0;
        } else {
            feitian_log(LOG_DEBUG, "ssl write error, code = %d", ret);
            return -1;
        }
    }

    return writtenLen;

}

int32_t HAL_SSL_Destroy(uintptr_t handle)
{
    if ((uintptr_t)NULL == handle) {
        feitian_log(LOG_DEBUG, "handle is NULL\n");
        return 0;
    }

    IotTlsDataParams_t *ssl = (IotTlsDataParams_t *)handle;


    mbedtls_ssl_close_notify(&(ssl->ssl_ctx));
    mbedtls_net_free(&(ssl->net_ctx));
    
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free(&ssl->cacert);
    if ((ssl->pkey).pk_info != NULL) {
        feitian_log(LOG_DEBUG, "need release client crt&key\n");
#if defined(MBEDTLS_CERTS_C)
    mbedtls_x509_crt_free(&ssl->clicert);
        mbedtls_pk_free(&(ssl->pkey));
#endif
    }
#endif
    mbedtls_ssl_free(&ssl->ssl_ctx);    
    mbedtls_ssl_config_free(&ssl->ssl_conf);
    mbedtls_ctr_drbg_free(&ssl->ctr_drbg);
    mbedtls_entropy_free(&ssl->entropy);               


    g_ssl_hooks.free((void *)handle);
    return 0;
}

int ssl_hooks_set(ssl_hooks_t *hooks)
{
    if (hooks == NULL || hooks->malloc == NULL || hooks->free == NULL) {
        return -1;
    }

    g_ssl_hooks.malloc = hooks->malloc;
    g_ssl_hooks.free = hooks->free;

    return 0;
}

uintptr_t HAL_SSL_Establish(const char *host,
                            uint16_t port,
                            const char *ca_crt,
                            uint32_t ca_crt_len)
{

    const char *pers = "bsjiot";
    int value, ret = 0; 
    uint32_t flags;
    char port_s[10] = {0};
    IotTlsDataParams_t *ssl;

    ssl = HAL_Malloc(sizeof(IotTlsDataParams_t));
    if (!ssl) {
        feitian_log(LOG_DEBUG, "Memory malloc error.");
        ret = -1;
        goto exit;
    }
       /*
     * Initialize the RNG and the session data
     */
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif
    ssl->net_ctx.fd = -1;
    mbedtls_ssl_init(&ssl->ssl_ctx);
    mbedtls_ssl_config_init(&ssl->ssl_conf);
    mbedtls_x509_crt_init(&ssl->cacert);
    mbedtls_x509_crt_init(&ssl->clicert);
    mbedtls_pk_init(&ssl->pkey);
    mbedtls_ctr_drbg_init(&ssl->ctr_drbg);
    mbedtls_entropy_init(&ssl->entropy);    
    if ((value = mbedtls_ctr_drbg_seed(&ssl->ctr_drbg,
                               mbedtls_entropy_func, 
                               &ssl->entropy,
                               (const unsigned char*)pers,
                               strlen(pers))) != 0) {       
        feitian_log(LOG_DEBUG, "mbedtls_ctr_drbg_seed() failed, value:-0x%x.", -value);
        ret = -1;
        goto exit;
    }

    /*
    * Load the trusted CA
    */    
    /* cert_len passed in is gotten from sizeof not strlen */
    if (0 != (ret = mbedtls_x509_crt_parse(&ssl->cacert, (const unsigned char *)ca_crt, ca_crt_len))) {
        feitian_log(LOG_DEBUG, " failed ! x509parse_crt returned -0x%04x\n", -ret);
        return ret;
    }
    
     /*
     * Start the connection
     */
    snprintf(port_s, sizeof(port_s), "%d", port) ;
    feitian_log(LOG_DEBUG, "Connecting to addr %s...", host);
    feitian_log(LOG_DEBUG, "Connecting to port %d,line %d...", port,__LINE__);

    if ((ret = mbedtls_net_connect(&ssl->net_ctx, host, port_s, MBEDTLS_NET_PROTO_TCP)) != 0) {
        feitian_log(LOG_DEBUG, "failed! mbedtls_net_connect returned %d, port:%s.", ret, port);
        goto exit;
    }  

    /*
     * Setup stuff
     */
    if ((value = mbedtls_ssl_config_defaults(&ssl->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {        
        feitian_log(LOG_DEBUG, "mbedtls_ssl_config_defaults() failed, value:-0x%x.", -value);
        ret = -1;
        goto exit;
    }
    // TODO: add customerization encryption algorithm

    /*
     * Setup stuff
     */
    if ((value = mbedtls_ssl_config_defaults(&ssl->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {        
        feitian_log(LOG_DEBUG, "mbedtls_ssl_config_defaults() failed, value:-0x%x.", -value);
        ret = -1;
        goto exit;
    }

    // TODO: add customerization encryption algorithm
    memcpy(&ssl->profile, ssl->ssl_conf.cert_profile, sizeof(mbedtls_x509_crt_profile));    
    ssl->profile.allowed_mds = ssl->profile.allowed_mds | MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_MD5);
    mbedtls_ssl_conf_cert_profile(&ssl->ssl_conf, &ssl->profile);
    

    if (ca_crt != NULL) {
#if defined(FORCE_SSL_VERIFY)
        mbedtls_ssl_conf_authmode(&ssl->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#else
        mbedtls_ssl_conf_authmode(&ssl->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#endif
    } else {
        mbedtls_ssl_conf_authmode(&ssl->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    }
    
    mbedtls_ssl_conf_ca_chain(&ssl->ssl_conf, &ssl->cacert, NULL);

    if ((ret = mbedtls_ssl_conf_own_cert(&ssl->ssl_conf, &ssl->clicert, &ssl->pkey)) != 0) {
        feitian_log(LOG_DEBUG, " failed! mbedtls_ssl_conf_own_cert returned %d.", ret );
        goto exit;
    }

    mbedtls_ssl_conf_rng(&ssl->ssl_conf, mbedtls_ctr_drbg_random, &ssl->ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl->ssl_conf, _ssl_debug, NULL);

    if ((value = mbedtls_ssl_setup(&ssl->ssl_ctx, &ssl->ssl_conf)) != 0) {
        feitian_log(LOG_DEBUG, "mbedtls_ssl_setup() failed, value:-0x%x.", -value);
        ret = -1;
        goto exit;
    }   

    mbedtls_ssl_set_bio(&ssl->ssl_ctx, &ssl->net_ctx, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);    
    //mbedtls_ssl_set_timer_cb( &ssl->ssl_ctx, &ssl->timer, mbedtls_timing_set_delay,
    //                                       mbedtls_timing_get_delay );
    
    /*
    * Handshake
    */
    while ((ret = mbedtls_ssl_handshake(&ssl->ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {      
            feitian_log(LOG_DEBUG, "mbedtls_ssl_handshake() failed, ret:-0x%x.", -ret);
            ret = -1;
            goto exit;
        }
    }

    /*
     * Verify the server certificate
     */
    /* In real life, we would have used MBEDTLS_SSL_VERIFY_REQUIRED so that the
        * handshake would not succeed if the peer's cert is bad.  Even if we used
        * MBEDTLS_SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
    if (0 != (ret = _real_confirm(mbedtls_ssl_get_verify_result(&ssl->ssl_ctx)))) {
        char vrfy_buf[512];
        feitian_log(LOG_DEBUG, "svr_cert varification failed.");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        feitian_log(LOG_DEBUG, "%s", vrfy_buf);
    }
    else
        feitian_log(LOG_DEBUG, "svr_cert varification ok."); 

exit:
    feitian_log(LOG_DEBUG, "ret=%d.", ret);
    if(ret == 0)
    {
        return (uintptr_t)ssl;
    }
    else
    {
        return (uintptr_t)NULL;
    }

}
#endif
#else

uintptr_t HAL_TCP_Establish(const char *host, uint16_t port)
{
    struct sockaddr_in sAddr;
    struct hostent *host_entry = NULL;
    int fd = -1;
	int retVal = -1;
	
    if ((host_entry = socket_gethostbyname(host)) == NULL) {
        feitian_log(LOG_DEBUG, "dns parse error!");
		return -2;
    }

    sAddr.sin_family = AF_INET;
    sAddr.sin_port   = htons(port);
    sAddr.sin_addr   = *(struct in_addr *)host_entry->h_addr_list[0];
    feitian_log(LOG_DEBUG, "Connecting to addr %s...", host);
    feitian_log(LOG_DEBUG, "Connecting to port %d,line %d...", port,__LINE__);

    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        goto exit;
    }

    struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;

	sock_fd_set readfds, writefds;
    int error;
    socklen_t optlen = sizeof(error);
	
	SOCK_FD_ZERO(&readfds);
	SOCK_FD_ZERO(&writefds);
	SOCK_FD_SET(fd, &readfds);
	SOCK_FD_SET(fd, &writefds);
	
    retVal = socket_connect(fd, (struct sockaddr*)&sAddr, sizeof(sAddr));
    if (retVal == 0) {
        feitian_log(LOG_DEBUG, "connect success....\n");
    } else {
        retVal = socket_select(fd+1, &readfds, &writefds, NULL, &tv);
        switch(retVal) {
            case -1:
                feitian_log(LOG_DEBUG, "connect failed!");
	            goto exit;
                break;
            case 0:
                feitian_log(LOG_DEBUG, "connect timeout!");
	            goto exit;
                break;
            default:
                if(!SOCK_FD_ISSET(fd, &readfds) && !SOCK_FD_ISSET(fd, &writefds)) {
                    feitian_log(LOG_DEBUG, "connect no response\n");
                    goto exit;
                } else if(SOCK_FD_ISSET(fd, &readfds) && SOCK_FD_ISSET(fd, &writefds)) {
                    retVal = socket_getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen);
                    if(retVal == 0 && error == 0) {
                        feitian_log(LOG_DEBUG, "connect success....\n");
                    } else {
                        feitian_log(LOG_DEBUG, "connect error....\n");
                        goto exit;
                    }
                } else if(!SOCK_FD_ISSET(fd, &readfds) && SOCK_FD_ISSET(fd, &writefds)) {
                    feitian_log(LOG_DEBUG, "connect success....\n");
                } else {
                    feitian_log(LOG_DEBUG, "connect error....\n");
                    goto exit;
                }
                break;
        }
	}

	int old_option = socket_fcntl( fd, F_GETFL, 0);
    int new_option = old_option & (~O_NONBLOCK);
    socket_fcntl( fd, F_SETFL, new_option );

	return (int)fd;

exit:
    if (fd > 0) {
        socket_close(fd);
    }
    
    return -1;
}

int HAL_TCP_Destroy(uintptr_t fd)
{
    if (fd > 0) {
        socket_close(fd);
    }

    return 0;
}

int32_t HAL_TCP_Write(uintptr_t fd, const char *buf, uint32_t len, uint32_t timeout_ms)
{
    struct timeval tv;
    int sentLen = 0;

    //BSJ_LOG("enter ...");
    
    tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

    tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
    socket_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval));
    do {
		int rc = socket_send(fd, buf + sentLen, len - sentLen, 0);
		if (rc > 0) {
			sentLen += rc;
		} else if (rc < 0){
		    sentLen = rc;
            feitian_log(LOG_DEBUG, "send timeout, errno = %d", socket_geterrno());
			break;
		} else if (rc == 0){
		    sentLen = rc;
		    feitian_log(LOG_DEBUG, "err, send error happen, errno = %d", socket_geterrno());
		    break;
		}
	} while (sentLen < len);

    //BSJ_LOG("exit ...");
	return sentLen;
}

int32_t HAL_TCP_Read(uintptr_t fd, char *buf, uint32_t len, uint32_t timeout_ms)
{
    struct timeval tv;
    int recvLen = 0;

    tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

    socket_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    do {
	    int rc = socket_recv(fd, buf + recvLen, len - recvLen, 0);
		if (rc > 0) {
			recvLen += rc;
		} else if (rc < 0) {
		    if (recvLen > 0) {
		        feitian_log(LOG_DEBUG, "recv rsp done, size: %d", recvLen);
		    } else {
		        recvLen = 0;
                feitian_log(LOG_DEBUG, "recv timeout, no data");
		    }
		    break;
		} else if (rc == 0) {
		    if (recvLen > 0) {
		        feitian_log(LOG_DEBUG, "recv data done, size: %d", recvLen);
		    } else {
		        recvLen = -1;
                feitian_log(LOG_DEBUG, "err, recv error happen, errno = %d", socket_geterrno());
            }
			break;
		}
	} while (recvLen < len);
	
    //BSJ_LOG("exit ...");
	return recvLen;
}
#endif  /*SUPPORT_TLS*/


