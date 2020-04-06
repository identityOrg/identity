/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.config.doc;

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
//@EnableSwagger2
//@Import(BeanValidatorPluginsConfiguration.class)
public class SwaggerConfiguration {

//    @Autowired
//    private TypeResolver typeResolver;

    @Bean
    public OpenAPI springShopOpenAPI() {
        return new OpenAPI()
                .info(new Info().title("Identity API v1")
                        .description("Identity API specification")
                        .version("v1")
                        .license(new License().name("Apache 2.0").url("")))
                .externalDocs(new ExternalDocumentation()
                        .description("Project Source")
                        .url("https://github.com/identityOrg/identity.git"));
    }

    @Bean
    public GroupedOpenApi swaggerDocket() {
        return GroupedOpenApi.builder()
                .packagesToScan("net.prasenjit.identity.controller.audit",
                        "net.prasenjit.identity.controller.client",
                        "net.prasenjit.identity.controller.scope",
                        "net.prasenjit.identity.controller.claim",
                        "net.prasenjit.identity.controller.user",
                        "net.prasenjit.identity.controller.e2e")
                .setGroup("api")
                .build();
    }
//        List<Parameter> operationParameters = new ArrayList<>();
//        Parameter sessionParameter = new ParameterBuilder().name("X-Session-Id")
//                .parameterType("header").required(false)
//                .description("Latest Session id returned on the response header with same" +
//                        " name on any previous request")
//                .modelRef(new ModelRef("string")).build();
//        operationParameters.add(sessionParameter);
//        Parameter authorizationHeader = new ParameterBuilder().name("Authorization")
//                .parameterType("header").required(false)
//                .description("OAuth2 Bearer authorization token, maybe obtained by calling ant OAuth flow." +
//                        " Its required for all secured API call.")
//                .modelRef(new ModelRef("string")).build();
//        operationParameters.add(authorizationHeader);
//        return new Docket(DocumentationType.SWAGGER_2).select()
//                .apis(RequestHandlerSelectors.withClassAnnotation(SwaggerDocumented.class)).build()
//                .globalOperationParameters(operationParameters)
//                .globalResponseMessage(RequestMethod.POST, errorMessages())
//                .globalResponseMessage(RequestMethod.PUT, errorMessages())
//                .globalResponseMessage(RequestMethod.GET, errorMessages())
//                .globalResponseMessage(RequestMethod.DELETE, errorMessages())
//                .additionalModels(typeResolver.resolve(ApiError.class))
//                // .securitySchemes(getSecuritySchemes())
//                // .securityContexts(getSecurityContexts())
//                .directModelSubstitute(Duration.class, String.class)
//                .directModelSubstitute(URL.class, String.class)
//                .apiInfo(apiInfo());
//    }

//    private List<ResponseMessage> errorMessages() {
//        List<ResponseMessage> responseMessages = new ArrayList<>();
//        Map<String, Header> headers = new HashMap<>();
//        headers.put("X-Session-Id",
//                new Header("X-Session-Id", "Current session id associated with response",
//                        new ModelRef("string")));
//        responseMessages.add(
//                new ResponseMessage(401, "Un-authenticated", new ModelRef("ApiError"),
//                        headers, new ArrayList<>()));
//        responseMessages
//                .add(new ResponseMessage(403, "Un-authorized", new ModelRef("ApiError"),
//                        headers, new ArrayList<>()));
//        responseMessages
//                .add(new ResponseMessage(404, "Not Found", new ModelRef("ApiError"),
//                        headers, new ArrayList<>()));
//        responseMessages
//                .add(new ResponseMessage(400, "Invalid Request", new ModelRef("ApiError"),
//                        headers, new ArrayList<>()));
//        responseMessages.add(
//                new ResponseMessage(500, "Unexpected Error", new ModelRef("ApiError"),
//                        headers, new ArrayList<>()));
//        responseMessages
//                .add(new ResponseMessage(502, "Gateway Failed", new ModelRef("ApiError"),
//                        headers, new ArrayList<>()));
//        return responseMessages;
//    }
//
//    private ApiInfo apiInfo() {
//        return new ApiInfoBuilder().title("Identity API").description("Secure your app with the Identity API")
//                .license("Apache 2").termsOfServiceUrl("").version("1.0.0")
//                .contact(new Contact("Prasenjit Purohit", "http://www.prasenjit.net", "prasenjit@prasenjit.net"))
//                .build();
//    }
}
