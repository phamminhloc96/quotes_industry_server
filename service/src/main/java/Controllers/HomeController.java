package Controllers;


import APIs.IHomeController;

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
