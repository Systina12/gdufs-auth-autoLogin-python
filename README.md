# gdufs-auth-autoLogin
一个用于自动化登录广东外语外贸大学教务 SSO 系统的python程序，自动处理验证码及其他校验流程，获取登录后的 token，可用于各类教务系统自动化项目。   
广外SSO : authserver.gdufs.edu.cn   
实例化GdufsAuthAutoLogin类，传入Session,Username,password参数，调用login函数即可登录
