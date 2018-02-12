package net.prasenjit.identity.doc;

import com.fasterxml.classmate.TypeResolver;
import net.prasenjit.identity.model.ApiError;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.RequestMethod;
import springfox.bean.validators.configuration.BeanValidatorPluginsConfiguration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.net.URL;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
@EnableSwagger2
@Import(BeanValidatorPluginsConfiguration.class)
public class SwaggerConfiguration {

    @Autowired
    private TypeResolver typeResolver;

    @Bean
    public Docket swaggerDocket() {
        List<Parameter> operationParameters = new ArrayList<>();
        Parameter sessionParameter = new ParameterBuilder().name("X-Session-Id")
                .parameterType("header").required(false)
                .description("Latest Session id returned on the response header with same" +
                        " name on any previous request")
                .modelRef(new ModelRef("string")).build();
        operationParameters.add(sessionParameter);
        Parameter authorizationHeader = new ParameterBuilder().name("Authorization")
                .parameterType("header").required(false)
                .description("OAuth2 Bearer authorization token, maybe obtained by calling ant OAuth flow." +
                        " Its required for all secured API call.")
                .modelRef(new ModelRef("string")).build();
        operationParameters.add(authorizationHeader);
        return new Docket(DocumentationType.SWAGGER_2).select()
                .apis(RequestHandlerSelectors.withClassAnnotation(SwaggerDocumented.class)).build()
                .globalOperationParameters(operationParameters)
                .globalResponseMessage(RequestMethod.POST, errorMessages())
                .globalResponseMessage(RequestMethod.PUT, errorMessages())
                .globalResponseMessage(RequestMethod.GET, errorMessages())
                .globalResponseMessage(RequestMethod.DELETE, errorMessages())
                .additionalModels(typeResolver.resolve(ApiError.class))
                // .securitySchemes(getSecuritySchemes())
                // .securityContexts(getSecurityContexts())
                .directModelSubstitute(Duration.class, String.class)
                .directModelSubstitute(URL.class, String.class)
                .apiInfo(apiInfo());
    }

    // private List<SecurityContext> getSecurityContexts() {
    // List<SecurityContext> securityContexts = new ArrayList<>();
    // List<SecurityReference> ref = new ArrayList<>();
    // ref.add(SecurityReference.builder()
    //
    // .build());
    // securityContexts.add(new SecurityContext(ref, sel));
    // return securityContexts;
    // }

    // private List<SecurityScheme> getSecuritySchemes() {
    // List<SecurityScheme> schemes = new ArrayList<>();
    // List<AuthorizationScope> scopes = new ArrayList<>();
    // scopes.add(new AuthorizationScope("openid", "default scope"));
    // List<GrantType> grants = new ArrayList<>();
    // grants.add(new
    // ResourceOwnerPasswordCredentialsGrant("http://localhost:8080/oauth/token"));
    // grants.add(new ClientCredentialsGrant("http://localhost:8080/oauth/token"));
    // TokenRequestEndpoint codeEp = new
    // TokenRequestEndpoint("http://localhost:8080/oauth/authorize",
    // "client_id", "client_secret");
    // TokenEndpoint tokenEp = new
    // TokenEndpoint("http://localhost:8080/oauth/token", "auth");
    // grants.add(new AuthorizationCodeGrant(codeEp, tokenEp));
    // LoginEndpoint loginEp = new
    // LoginEndpoint("http://localhost:8080/oauth/authorize");
    // grants.add(new ImplicitGrant(loginEp, "imp"));
    // schemes.add(new OAuth("Oauth2", scopes, grants));
    // return schemes;
    // }

    private List<ResponseMessage> errorMessages() {
        List<ResponseMessage> responseMessages = new ArrayList<>();
        Map<String, Header> headers = new HashMap<>();
        headers.put("X-Session-Id",
                new Header("X-Session-Id", "Current session id associated with response",
                        new ModelRef("string")));
        responseMessages.add(
                new ResponseMessage(401, "Un-authenticated", new ModelRef("ApiError"),
                        headers, new ArrayList<>()));
        responseMessages
                .add(new ResponseMessage(403, "Un-authorized", new ModelRef("ApiError"),
                        headers, new ArrayList<>()));
        responseMessages
                .add(new ResponseMessage(404, "Not Found", new ModelRef("ApiError"),
                        headers, new ArrayList<>()));
        responseMessages
                .add(new ResponseMessage(400, "Invalid Request", new ModelRef("ApiError"),
                        headers, new ArrayList<>()));
        responseMessages.add(
                new ResponseMessage(500, "Unexpected Error", new ModelRef("ApiError"),
                        headers, new ArrayList<>()));
        responseMessages
                .add(new ResponseMessage(502, "Gateway Failed", new ModelRef("ApiError"),
                        headers, new ArrayList<>()));
        return responseMessages;
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder().title("Identity API").description("Secure your app with the Identity API")
                .license("Apache 2").termsOfServiceUrl("").version("1.0.0")
                .contact(new Contact("Prasenjit Purohit", "http://www.prasenjit.net", "prasenjit@prasenjit.net"))
                .build();
    }
}
