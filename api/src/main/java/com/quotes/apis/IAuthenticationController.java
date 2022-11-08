package com.quotes.apis;

import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping(IAuthenticationController.ROOT_ENDPOINT)
public interface IAuthenticationController {
    String ROOT_ENDPOINT = "/api/v1/auth";
    String DELETE_EXPIRED_TOKEN = "/delete-expired-token";

//    @PostMapping("/login")
//    AuthTokensDto login(@RequestBody LoginRequest loginRequest,
//                        @RequestParam(value = "noRefreshToken", required = false, defaultValue = "false") Boolean noRefreshToken);
//
//    @PostMapping("/otp/login")
//    AuthTokensDto otpLogin(@RequestBody CredentialsDto credentials,
//                           @RequestParam(value = "noRefreshToken", required = false, defaultValue = "false") Boolean noRefreshToken);
//
//    @PostMapping("/otp/generate")
//    void otpGenerate(@RequestBody CredentialsDto credentials);
//
//    @PostMapping("/otp/clear")
//    void clearOtp(@RequestBody CredentialsDto credentials);
//
//    @GetMapping("/myself")
//    UserDto getMyself();
//
//    @PostMapping("/refresh")
//    AuthTokensDto refreshToken();
//
//    @PostMapping("/logout")
//    void logout();
//
//    @PostMapping("/users/check-exists")
//    boolean checkUserExists(@RequestParam(value = "userName") String userName);
//
//    @PostMapping("/users")
//    UserDto createUser(@RequestBody UserCreateRequest userCreateRequest);
//
//    @PatchMapping("/users/{id}")
//    UserDto updateUser(@PathVariable("id") UUID userID, @RequestBody UserUpdateRequest userUpdateRequest);
//
//    @PatchMapping("/users/{id}/lock-user")
//    UserDto lockUser(@PathVariable("id") UUID userID);
//
//    @PatchMapping("/users/{id}/unlock-user")
//    UserDto unLockUser(@PathVariable("id") UUID userID);
//
//    @PatchMapping("/users/{id}/reset-password")
//    UserDto resetPassword(@PathVariable("id") UUID userId, @RequestBody UserUpdateRequest request);
//
//    @GetMapping(IAuthenticationController.DELETE_EXPIRED_TOKEN)
//    @ResponseStatus(HttpStatus.NO_CONTENT)
//    void deleteExpiredToken();
//
//   /*@PostMapping("/encrypt-string")
//   String encryptString(@RequestBody String string);*/
//
//    @PostMapping("/get-token-pci")
//    AuthTokensDto getTokenPci(@RequestBody PciTokenRequest request);
//
//    @PostMapping("/send-verification-code")
//    UserVerificationCodeDto sendVerificationCode(@RequestBody CredentialsDto credentials);
//
//    @PostMapping("/check-verification-code")
//    UserVerificationCodeDto checkVerificationCode(@RequestBody CredentialsDto credentials);
//
//    @PostMapping("/update-user-forgot-password")
//    UserVerificationCodeDto updateUserForgotPassword(@RequestBody UserUpdateRequest request);
//
//    @PostMapping("/check-active-user")
//    UserVerificationCodeDto checkActiveUser(@RequestBody CredentialsDto credentials);
}
