package org.example;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URISyntaxException;

public class App {

    public static void main(String... args)  {
        try {
            Examples.getCallerIdentity();
            Examples.getSessionToken();
            Examples.assumeRole();
            Examples.assumeRoleWithPolicy();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
