package com.mmall.service;

import com.mmall.common.ServerResponse;
import com.mmall.pojo.User;

public interface IUserService {

    ServerResponse<User> login(String username, String password);

    ServerResponse<String> register(User user);

    ServerResponse<String> checkValid(String username, String password);

    ServerResponse checkAnswer(String username, String question, String answer);

    ServerResponse<String> forgetResetPassword(String username, String passwordnew, String forgetToken);

    ServerResponse<String> resetPassword(String passwordOld, String passwordNew, User user);

    ServerResponse checkAdminRole(User user);

}
