package net.sourceforge.spnego;

public class Strings
{
    public static boolean isBlank(String value) {
        if (value == null) {
            return true;
        }
        
        if (value.length() == 0) {
            return true;
        }
        
        if (value.trim().length() == 0) {
            return true;
        }
        
        return false;
    }
}
