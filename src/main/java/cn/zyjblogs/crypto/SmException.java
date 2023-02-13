package cn.zyjblogs.crypto;

/**
 * @author zhuyijun
 * @version 1.0.0
 * @description SM异常类
 * @create 2022/12/13 15:37
 */
public class SmException extends RuntimeException {
    public SmException() {
    }

    public SmException(String message) {
        super(message);
    }

    public SmException(String message, Throwable cause) {
        super(message, cause);
    }

    public SmException(Throwable cause) {
        super(cause);
    }

    public SmException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
