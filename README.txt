Pre-conditions to run the application:
1 Configured CAS url and other properties in application.propeties.
2 CAS server up and running.

Usage:
1 Launch Casified Secured Server: cd CAS-SECURED-ANGULAR-SPRING_BOOT_DEMO>gradle bootRun
2 In browser: http:localhost:9090
3 If there is no active CAS session (valid tgc in browser)then application will be redirected to CAS. 
4 Enter credentials on CAS login page and hit enter. On successful authenticating user will be redirected back to the application. 
5 On reaching back user can see his profile information. 

Steps to CASify your Spring Boot application:
1 Import CAS and Spring Security in classpath. Gradle builds can use below: 
	compile "org.springframework.boot:spring-boot-starter-security"
	compile "org.springframework.security:spring-security-cas"
2 Copy all packages and respective source files into your project. Namely :org.eso.example.controller, org.eso.example.security.
3 Put appropriate values in application.properties. 


   
     

