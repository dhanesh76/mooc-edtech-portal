package com.dhanesh.auth.portal.exception;

public class UsernameAlreadyTakenException extends RuntimeException{
    public UsernameAlreadyTakenException(String message){
        super(message);
    }
}
