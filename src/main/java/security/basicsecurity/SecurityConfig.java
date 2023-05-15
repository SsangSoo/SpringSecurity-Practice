package security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    UserDetailsService userDetailsService;

        // FormLogin
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        // 인가
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated();
//
//        // 인증
//        http
//                .formLogin()
////                .loginPage("/loginPage")        // 로그인 페이지
//                .defaultSuccessUrl("/")           // 인증 성공 후 Url
//                .failureUrl("/login")             // 인증 실패시 Url
//                .usernameParameter("userId")      // 아이디 파라미터명 설정
//                .passwordParameter("passwd")      // 패스워드 파라미터명 설정
//                .loginProcessingUrl("/login-proc")  // 로그인 Form Action Url
//                .successHandler(new AuthenticationSuccessHandler() {    // 로그인 성공 후 핸들러
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication : " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {    // 로그인 실패 후 핸들러
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll();
//
//        // 로그아웃
//        http
//                .logout()               // 시큐리티는 로그아웃을 원칙적으로는 POST 메서드 사용
//                .logoutUrl("/logout")   // 그런데 Get도 설정시 가능하긴함.
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();   // 세션 무효화
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember me") // 로그아웃시 삭제될 쿠키이름.
//                ;
//
//        // Remember Me
//        http
//                .rememberMe()
//                .rememberMeParameter("remember")          // 기본 파라미터명은 remember-me
//                .tokenValiditySeconds(3600)               // Default 14일 // 단위 : 초
//                .alwaysRemember(false)                    // 리멤버 미 기능이 활성화되지 않아도 항상 실행   // default값은 false라서 굳이 안 적어도 됨(소스코드 독스 참조)
//                .userDetailsService(userDetailsService)   // 리멤버미 기능 사용시 시스템에서 사용자 계정을 조회할 때 필요한 클래스 및 메서드
//        ;
//
//        // Session 동시 제어
//        http
//                .sessionManagement()
//                .invalidSessionUrl("/invalid")    // 세션이 유효하지 않을 때 이동할 페이지
//                .maximumSessions(1)               // 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용
//                .maxSessionsPreventsLogin(true)   // 동시 로그인 차단함(현재 사용자 인증 실패-최근 사용자 로그인 거부), false : 기존 세션 만료전략 (default)
//                .expiredUrl("/expried")           // 세션이 만료된 경우 이동 할 페이지
//        ;

//        // 세션 고정 보호
//        http
//                .sessionManagement()      // 세션 관리 기능이 동작
//                .sessionFixation()        // 세션 고정
//                      .changeSessionId()  // 기본값 - 세션 Id만 변경 // 서블릿 3.1 이상의 기본값
//                      .none()             // 설정 안함.
//                      .migrateSession()   // changeSessionId()와 동일하지만, 서블릿 3.1 이하의 기본값 -> 즉 몰라도된다. 지금 9.0이다..;;
//                      .newSession();      // 기본값과 다른 점은 새로운 세션과 ID가 발급되지만, 이전에 있었던 세부설정을 사용하지 못한다.
//         // 세션 정책
//         http
//                .sessionManagement()  // 세션 관리 기능이 동작
//                      .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)        // 스프링 시큐리티가 항상 세션 생성
//                      .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)   // 스프링 시큐리티가 필요시 생성(기본값)
//                      .sessionCreationPolicy(SessionCreationPolicy.NEVER)         // 스프링 시큐리티가 생성하지 않지만 이지 존재하면 사용
//                      .sessionCreationPolicy(SessionCreationPolicy.STATELESS)     // 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음. // 보통 JWT 사용시 적용


//    }



    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");

    }


    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                //
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                // 주석 중간의 두 줄의 위치를 바꾸면, sys 계정으로 로그인하고도 /admin/** , /admin/pay로 접근 가능함.
                .anyRequest().authenticated();
        http
                .formLogin();

    }


}
