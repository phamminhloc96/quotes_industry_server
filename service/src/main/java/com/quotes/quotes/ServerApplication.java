package com.quotes.quotes;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(exclude={DataSourceAutoConfiguration.class})
@EnableScheduling
@EnableCaching
public class ServerApplication extends SpringBootServletInitializer {

	protected static final Log logger = LogFactory.getLog(ServerApplication.class);

	public static void main(String[] args) {
		try {
			new SpringApplicationBuilder()
					.bannerMode(Banner.Mode.CONSOLE)
					.sources(ServerApplication.class)
					.run(args);
		} catch (Exception e) {
			logger.error("Application crashed " + e.getMessage(), e);
		}
	}

}
