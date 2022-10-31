package APIs;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/home")
public interface IHomeController {

    @GetMapping()
    public String home();

    @GetMapping()
    public String about();

}
