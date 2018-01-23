package net.prasenjit.identity.doc;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMethod;

import com.fasterxml.classmate.TypeResolver;

import net.prasenjit.identity.model.ApiError;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.service.Header;
import springfox.documentation.service.Parameter;
import springfox.documentation.service.ResponseMessage;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfiguration {

	@Autowired
	private TypeResolver typeResolver;

	@Bean
	public Docket swaggerDocket() {
		List<Parameter> operationParameters = new ArrayList<>();
		Parameter sessionParameter = new ParameterBuilder().name("X-Session-Id").parameterType("header").required(false)
				.description("Latest Session id returned on the response header with same name on any previous request")
				.modelRef(new ModelRef("string")).build();
		operationParameters.add(sessionParameter);
		return new Docket(DocumentationType.SWAGGER_2).select()
				.apis(RequestHandlerSelectors.withClassAnnotation(SwaggerDocumented.class)).build()
				.globalOperationParameters(operationParameters)
				.globalResponseMessage(RequestMethod.POST, errorMessages())
				.globalResponseMessage(RequestMethod.PUT, errorMessages())
				.globalResponseMessage(RequestMethod.GET, errorMessages())
				.globalResponseMessage(RequestMethod.DELETE, errorMessages())
				.additionalModels(typeResolver.resolve(ApiError.class)).apiInfo(apiInfo());
	}

	private List<ResponseMessage> errorMessages() {
		List<ResponseMessage> responseMessages = new ArrayList<>();
		Map<String, Header> headers = new HashMap<>();
		headers.put("X-Session-Id",
				new Header("X-Session-Id", "Current session id associated with response", new ModelRef("string")));
		responseMessages.add(
				new ResponseMessage(401, "Un-authenticated", new ModelRef("ApiError"), headers, new ArrayList<>()));
		responseMessages
				.add(new ResponseMessage(403, "Un-authorized", new ModelRef("ApiError"), headers, new ArrayList<>()));
		responseMessages
				.add(new ResponseMessage(404, "Not Found", new ModelRef("ApiError"), headers, new ArrayList<>()));
		responseMessages
				.add(new ResponseMessage(400, "Invalid Request", new ModelRef("ApiError"), headers, new ArrayList<>()));
		responseMessages.add(
				new ResponseMessage(500, "Unexpected Error", new ModelRef("ApiError"), headers, new ArrayList<>()));
		responseMessages
				.add(new ResponseMessage(502, "Gateway Failed", new ModelRef("ApiError"), headers, new ArrayList<>()));
		return responseMessages;
	}

	private ApiInfo apiInfo() {
		return new ApiInfoBuilder().title("Identity API").description("Secure your app with the Identity API")
				.license("Apache 2").termsOfServiceUrl("").version("1.0.0")
				.contact(new Contact("Prasenjit Purohit", "http://www.prasenjit.net", "prasenjit@prasenjit.net"))
				.build();
	}
}
