一、为何要升级到spring boot3？
因为新发布的spring boot3本身就支持spring native了，意味着可以用更小的内存和更快的启动速度，而更小的内存意味着服务器可以运行更多的项目，节约成本。所以第一步，先升级到spring boot3，不要再用之前旧的低于spring boot3版本的方式去实现spring native了。本文以若依前后端分离单体版为演示版本。

二、升级步骤
1、安装jdk17
低版本jdk不支持，必须至少采用jdk17

https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.exe
2、下载若依

https://github.com/yangzongzhuan/RuoYi-Vue-fast

3、导入项目，修改jdk
idea需用2022.2或更高版本

先修改pom文件spring boot版本，改为3.0.2

然后再导入

最后修改jdk版本，怎么修改jdk就不赘述了

4、javaee转jakara

使用idea自带的转换功能







5、再次修改pom

这时候会有一些报错，需要修改pom

fork配置注释掉

复制代码
<plugin>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-maven-plugin</artifactId>
<configuration>
<!-- <fork>true</fork>  如果没有该配置，devtools不会生效 -->
</configuration>
</plugin>
复制代码
缺失javax.xml.bing,则添加依赖

<dependency>
    <groupId>javax.xml.bind</groupId>
    <artifactId>jaxb-api</artifactId>
    <version>2.3.0</version>
</dependency>

6、spring boot3对应的spring security6,需采用新的配置方式，

SecurityConfig.java文件改为以下,且路径通配符**需改为*

复制代码
package com.ruoyi.framework.config;

import com.ruoyi.framework.security.filter.JwtAuthenticationTokenFilter;
import com.ruoyi.framework.security.handle.AuthenticationEntryPointImpl;
import com.ruoyi.framework.security.handle.LogoutSuccessHandlerImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.filter.CorsFilter;

/**
* spring security配置
*
* @author ruoyi
  */
  @EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
  @Configuration
  public class SecurityConfig
  {
  /**
    * 自定义用户认证逻辑
      */
      @Autowired
      private UserDetailsService userDetailsService;

  /**
    * 认证失败处理类
      */
      @Autowired
      private AuthenticationEntryPointImpl unauthorizedHandler;

  /**
    * 退出处理类
      */
      @Autowired
      private LogoutSuccessHandlerImpl logoutSuccessHandler;

  /**
    * token认证过滤器
      */
      @Autowired
      private JwtAuthenticationTokenFilter authenticationTokenFilter;

  /**
    * 跨域过滤器
      */
      @Autowired
      private CorsFilter corsFilter;

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
  return authenticationConfiguration.getAuthenticationManager();
  }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                // CSRF禁用，因为不使用session
                .csrf().disable()
                // 禁用HTTP响应标头
                .headers().cacheControl().disable().and()
                // 认证失败处理类
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                // 基于token，所以不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                // 过滤请求
                .authorizeRequests()
                // 对于登录login 注册register 验证码captchaImage 允许匿名访问
                .requestMatchers("/login", "/register", "/captchaImage").permitAll()
                // 静态资源，可匿名访问
                .requestMatchers(HttpMethod.GET, "/", "/*.html", "/*/*.html", "/*/*.css", "/*/*.js", "/profile/*").permitAll()
                .requestMatchers("/swagger-ui.html", "/swagger-resources/*", "/webjars/*", "/*/api-docs", "/druid/*").permitAll()
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated()
                .and()
                .headers().frameOptions().disable();
        // 添加Logout filter
        httpSecurity.logout().logoutUrl("/logout").logoutSuccessHandler(logoutSuccessHandler);
        // 添加JWT filter
        httpSecurity.addFilterBefore(authenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        // 添加CORS filter
        httpSecurity.addFilterBefore(corsFilter, JwtAuthenticationTokenFilter.class);
        httpSecurity.addFilterBefore(corsFilter, LogoutFilter.class);

        return httpSecurity.build();
    }
    /**
     * 强散列哈希加密实现
     */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    /**
     * 身份认证接口
     */
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }
}

7、关闭com.alibaba.druid数据库监听功能

这玩意有安全隐患，漏扫会报告，感觉用处不大，而且启动也报错误，application-druid.yml相关配置改为false即可

statViewServlet:
enabled: false

8、再次修改pom
此时可尝试启动，若启动失败，报mybatis相关错误，则需要将mybatis-spring-boot-starter升级到最新版本，默认版本不支持spring boot3

升级到

<dependency>
            <groupId>org.mybatis.spring.boot</groupId>
            <artifactId>mybatis-spring-boot-starter</artifactId>
            <version>3.0.1</version>
</dependency>

9、启动

没有意外的话就没有意外了，可以启动成功，然后下载前端项目，运行访问后台。

10、后续

spring native打包测试。