package user.zc.casclient;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class TestCas {

    @RequestMapping("/test1")
    public String test1(){
        return "test1....";
    }
}