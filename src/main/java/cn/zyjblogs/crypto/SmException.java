package cn.zyjblogs.crypto;

/**
 * @author zhuyijun
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
