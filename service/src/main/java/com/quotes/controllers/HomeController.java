package com.quotes.controllers;

import com.quotes.apis.IHomeController;

public class HomeController implements IHomeController {
    @Override
    public String home() {
        return "Hello, world!";
    }

    @Override
    public String about() {
        return "";
    }
}
