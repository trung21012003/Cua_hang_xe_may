package com.example.cua_hang_xe_may.config;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
    @Configuration
    public class FileConfig {
        @Bean
        public ModelMapper modelMapper() {
            return new ModelMapper();
        }
    }

