package com.quotes.controllers;

//@RestController
public class AuthenticationController {
//        implements IAuthenticationController {
//    protected static final Log logger = LogFactory.getLog(AuthenticationController.class);
//    private final UserService userService;
//    private final TokenService tokenService;
//    private final RefreshTokenRepository refreshTokenRepository;
//    private final UserVerificationCodeRepository userVerificationCodeRepository;
//    private final IUserController iUserController;
//    private final CryptUtils cryptUtils = new CryptUtils();
//
//    public AuthenticationController(UserService userService,
//                                    TokenService tokenService,
//                                    RefreshTokenRepository refreshTokenRepository,
//                                    UserVerificationCodeRepository userVerificationCodeRepository,
//                                    ConfigReader configReader,
//                                    ClientFactory clientFactory) {
//        this.userService = userService;
//        this.tokenService = tokenService;
//        this.refreshTokenRepository = refreshTokenRepository;
//        this.userVerificationCodeRepository = userVerificationCodeRepository;
//        this.iUserController = clientFactory.buildRestClient(configReader.getManagementUrl(), IUserController.class,
//            new JwtSelfSigned(configReader));
//    }
//
//    @Override
//    public AuthTokensDto login(LoginRequest loginRequest, Boolean noRefreshToken) {
//        if (!loginRequest.getEmail().toLowerCase(Locale.ROOT).equals("digitexx") &&
//            !loginRequest.getEmail().toLowerCase(Locale.ROOT).equals("pfs-production") &&
//            !loginRequest.getEmail().toLowerCase(Locale.ROOT).equals("pfs-production-rtf")) {
//            if (this.iUserController.getActiveUsersByUserName(loginRequest.getEmail()) == null) {
//                ExceptionHelper.UNAUTHORIZED.throwCustomException(ErrorMessageKey.IncorrectUsernameorPassword, null);
//            }
//        }
//        String passwordOrigin = loginRequest.getPassword();
//        String password = loginRequest.getPassword();
//        Pattern pattern = Pattern.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");
//        Matcher matcher = pattern.matcher(password);
//        if (matcher.find()) {
//            byte[] passwordDecodedBytes = Base64.getDecoder().decode(password);
//            password = new String(passwordDecodedBytes);
//        }
//        return tokenService.generateTokensForUser(
//            userService.loadUserByUsernameAndPassword(
//                loginRequest.getEmail(),
//                password,
//                passwordOrigin
//            ),
//            Boolean.TRUE.equals(noRefreshToken)
//        );
//    }
//
//    @Override
//    public AuthTokensDto otpLogin(CredentialsDto credentials, Boolean noRefreshToken) {
//        if (!credentials.getEmail().toLowerCase(Locale.ROOT).equals("digitexx") &&
//            !credentials.getEmail().toLowerCase(Locale.ROOT).equals("pfs-production") &&
//            !credentials.getEmail().toLowerCase(Locale.ROOT).equals("pfs-production-rtf")) {
//            if (this.iUserController.getActiveUsersByUserName(credentials.getEmail()) == null) {
//                return null;
//            }
//        }
//        return tokenService.generateTokensForUser(
//            userService.loadUserByUsernameAndOtp(
//                credentials.getEmail()
//            ),
//            Boolean.TRUE.equals(noRefreshToken)
//        );
//    }
//
//    @Override
//    public void otpGenerate(CredentialsDto credentials) {
//        userService.otpAction(credentials.getEmail(), cryptUtils.encryptingPassword(PasswordGenerator.generate()));
//    }
//
//    @Override
//    public void clearOtp(CredentialsDto credentials) {
//        userService.otpAction(credentials.getEmail(), null);
//    }
//
//    @Override
//    public UserDto getMyself() {
//        User user = this.getAuthenticatedUser().getDetails();
//
//        UserDto userDto = new UserDto();
//        userDto.setId(user.getId());
//        userDto.setLockedAt(user.getLockedAt());
//        userDto.setExpiredAt(user.getExpiredAt());
//        userDto.setCreatedAt(user.getCreatedAt());
//        userDto.setUpdatedAt(user.getUpdatedAt());
//
//        return userDto;
//    }
//
//    @Override
//    public AuthTokensDto refreshToken() {
//        RefreshToken usedRefreshToken = tokenService.loadRefreshTokenByAuthenticatedUser(getAuthenticatedUser());
//        AuthTokensDto generatedTokens = tokenService.generateTokensForUser(getAuthenticatedUser().getDetails());
//        tokenService.deleteRefreshToken(usedRefreshToken);
//        return generatedTokens;
//    }
//
//    @Override
//    public void logout() {
//        RefreshToken refreshToken = tokenService.loadRefreshTokenByAuthenticatedUser(getAuthenticatedUser());
//        tokenService.deleteRefreshToken(refreshToken);
//    }
//
//    @Override
//    public boolean checkUserExists(String userName) {
//        return userService.checkUsernameExists(userName);
//    }
//
//    @Override
//    public UserDto createUser(UserCreateRequest userCreateRequest) {
//        User newUser = UserMapper.INSTANCE.map(userCreateRequest);
//
//        List<String> usernames = newUser.getUsernames().stream().map(Username::getName).collect(Collectors.toList());
//        if (userService.checkUsernameExists(usernames)) {
//            ExceptionHelper.BAD_REQUEST.throwCustomException(ErrorMessageKey.UserNameExist, null);
//        }
//
//        newUser = userService.createUser(newUser);
//        return UserMapper.INSTANCE.map(newUser);
//    }
//
//    @Override
//    public UserDto updateUser(UUID userId, UserUpdateRequest userUpdateRequest) {
//        if (!CollectionUtils.isEmpty(userUpdateRequest.getAddedUsernames()) &&
//            userService.checkUsernameExists(userUpdateRequest
//                .getAddedUsernames()
//                .stream()
//                .map(UsernameDto::getName)
//                .collect(Collectors.toList()))
//        ) {
//            ExceptionHelper.BAD_REQUEST.throwCustomException(ErrorMessageKey.UserNameExist, null);
//        }
//
//        User user = userService.loadUserById(userId);
//        updateUsernames(userUpdateRequest, user);
//        user = UserMapper.INSTANCE.map(userUpdateRequest, user);
//
//        if (userUpdateRequest.getNewPassword() != null) {
//            userService.updatePassword(user, userUpdateRequest.getCurrentPassword(), userUpdateRequest.getNewPassword());
//        }
//
//        userService.saveUser(user);
//
//        return UserMapper.INSTANCE.map(user);
//    }
//
//    private void updateUsernames(UserUpdateRequest userUpdateRequest, User user) {
//        if (!CollectionUtils.isEmpty(userUpdateRequest.getRemovedUsernames())) {
//            List<String> removedUsernames = userUpdateRequest.getRemovedUsernames()
//                .stream()
//                .map(UsernameDto::getName)
//                .collect(Collectors.toList());
//            user.getUsernames().removeAll(
//                user.getUsernames()
//                    .stream()
//                    .filter(username -> removedUsernames.contains(username.getName()))
//                    .collect(Collectors.toList())
//            );
//        }
//        if (!CollectionUtils.isEmpty(userUpdateRequest.getAddedUsernames())) {
//            user.getUsernames().addAll(UsernameMapper.INSTANCE.map(userUpdateRequest.getAddedUsernames(), user));
//        }
//        if (user.getUsernames().isEmpty()) {
//            ExceptionHelper.BAD_REQUEST.throwCustomException(ErrorMessageKey.UserNameMustHaveOne, null);
//        }
//    }
//
//    @Override
//    public UserDto lockUser(UUID userID) {
//        User user = userService.loadUserByIdNotCheck(userID);
//        user.setLockedAt(LocalDateTime.now());
//        userService.saveUser(user);
//        return UserMapper.INSTANCE.map(user);
//    }
//
//    @Override
//    public UserDto unLockUser(UUID userID) {
//        User user = userService.loadUserByIdNotCheck(userID);
//        if (user.getLockedAt() == null) {
//            return UserMapper.INSTANCE.map(user);
//        }
//        user.setLockedAt(null);
//        userService.saveUser(user);
//        return UserMapper.INSTANCE.map(user);
//    }
//
//    @Override
//    public UserDto resetPassword(UUID userId, UserUpdateRequest request) {
//        User user = userService.loadUserById(userId);
//        user.setPassword(cryptUtils.encryptingPassword(request.getNewPassword()));
//        user.setInitialPassword(request.isInitialPassword());
//        userService.saveUser(user);
//        return UserMapper.INSTANCE.map(user);
//    }
//
//    @Override
//    @Transactional
//    public void deleteExpiredToken() {
//        logger.info("Start Job: deleting expired Refresh Tokens");
//        int deleteCount = refreshTokenRepository.deleteAllByExpiredAtBefore(LocalDateTime.now());
//        logger.info("Finished Job: deleted " + deleteCount + " Refresh Tokens");
//    }
//
//    @Override
//    public AuthTokensDto getTokenPci(PciTokenRequest pciTokenRequest) {
//        return tokenService.generateTokenPciForUser(getAuthenticatedUser().getDetails(), pciTokenRequest);
//    }
//
//    private AuthenticatedUser getAuthenticatedUser() {
//        try {
//            return (AuthenticatedUser) SecurityContextHolder.getContext().getAuthentication();
//        } catch (ClassCastException e) {
//            throw ExceptionHelper.UNAUTHORIZED.throwException(e);
//        }
//    }
//
//    @Override
//    public UserVerificationCodeDto sendVerificationCode(CredentialsDto credentials) {
//        if (credentials.getEmail() == null) {
//            ExceptionHelper.NOT_FOUND.throwException(null, User.class.getCanonicalName(), "NO_DATA");
//        }
//        if (this.iUserController.getActiveUsersByUserName(credentials.getEmail()) == null) {
//            UserVerificationCodeDto userVerificationCodeDto = new UserVerificationCodeDto();
//            userVerificationCodeDto.setMessage("de_active_user");
//            return userVerificationCodeDto;
//        }
//        String verificationCode = this.generateVerificationCode();
//        //store Verification Code and Infor here.
//        UserVerificationCode userVerificationCode = userService.getUsernameIgnoreCheckTime(credentials.getEmail());
//        if (userVerificationCode == null) {
//            userVerificationCode = new UserVerificationCode();
//        }
//        if (userService.checkUsernameExists(credentials.getEmail())) {
//            //if verification code of this user exists in database, set usedFlag = false before send new one
//            //userService.checkUsernameExists(credentials.getEmail())
//            User userInfo = userService.loadUserByUsername(credentials.getEmail());
//            userVerificationCode.setUsername(credentials.getEmail());
//            userVerificationCode.setUserId(userInfo.getId());
//            userVerificationCode.setVerificationCode(verificationCode);
//            userVerificationCode.setCreatedAt(LocalDateTime.now());
//            userVerificationCode.setExpiredAt(LocalDateTime.now().plusDays(1));
//            userVerificationCodeRepository.save(userVerificationCode);
//
//            try {
//                credentials.setVerificationCode(verificationCode);
//                this.iUserController.sendVerificationCodeResetPassword(credentials);
//            } catch (Exception e) {
//                logger.warn("Error When Sending Verification Code ", e);
//            }
//        }
//        return UserVerificationCodeMapper.INSTANCE.map(userVerificationCode);
//    }
//
//    @Override
//    public UserVerificationCodeDto checkVerificationCode(CredentialsDto credentials) {
//
//        UserVerificationCode userVerificationCode = userService.getUsernameExists(credentials.getEmail());
//
//        UserVerificationCodeDto userVerificationCodeDto = UserVerificationCodeMapper.INSTANCE.map(userVerificationCode);
//        if (userVerificationCode != null) {
//            if (credentials.getVerificationCode().equals(userVerificationCode.getVerificationCode())) {
//                userVerificationCodeDto.setCorrectCode(true);
//            }
//        } else {
//            userVerificationCodeDto = new UserVerificationCodeDto();
//            userVerificationCodeDto.setCorrectCode(false);
//        }
//        return userVerificationCodeDto;
//    }
//
//    @Override
//    public UserVerificationCodeDto updateUserForgotPassword(UserUpdateRequest request) {
//        if (this.iUserController.getActiveUsersByUserName(request.getUsername()) == null) {
//            UserVerificationCodeDto userVerificationCodeDto = new UserVerificationCodeDto();
//            userVerificationCodeDto.setMessage("de_active_user");
//            return userVerificationCodeDto;
//        }
//        UserVerificationCode userVerificationCode = userService.getUsernameExists(request.getUsername());
//        UserVerificationCodeDto userVerificationCodeDto = UserVerificationCodeMapper.INSTANCE.map(userVerificationCode);
//        if (userVerificationCode != null) {
//            if (request.getVerificationCode().equals(userVerificationCode.getVerificationCode())) {
//                userVerificationCodeDto.setCorrectCode(true);
//                User user = userService.loadUserByUsername(request.getUsername());
//                if (request.getNewPassword() != null) {
//                    user.setPassword(cryptUtils.encryptingPassword(request.getNewPassword()));
//                    userService.saveUser(user);
//                    userVerificationCode.setUsed(true);
//                    userVerificationCodeRepository.save(userVerificationCode);
//                } else {
//                    ExceptionHelper.BAD_REQUEST.throwCustomException(ErrorMessageKey.PasswordNotBlank, null);
//                }
//            }
//        } else {
//            userVerificationCodeDto = new UserVerificationCodeDto();
//            userVerificationCodeDto.setCorrectCode(false);
//        }
//        return userVerificationCodeDto;
//    }
//
//    protected static String generateVerificationCode() {
//        String listSeq = String.join("",
//            () -> IntStream.rangeClosed(0, 9).mapToObj(x -> (CharSequence) String.valueOf(x)).iterator());
//
//        StringBuilder rdResult = new StringBuilder();
//        Random rnd = new Random();
//        while (rdResult.length() < 8) { // length of the random string.
//            int index = (int) (rnd.nextFloat() * listSeq.toString().length());
//            rdResult.append(listSeq.toString().charAt(index));
//        }
//        return rdResult.toString();
//
//    }
//
//    @Override
//    public UserVerificationCodeDto checkActiveUser(CredentialsDto credentials) {
//        UserVerificationCodeDto userVerificationCodeDto = new UserVerificationCodeDto();
//        if (this.iUserController.getActiveUsersByUserName(credentials.getEmail()) == null) {
//            userVerificationCodeDto.setMessage("de_active_user");
//        } else {
//            userVerificationCodeDto.setUsername(credentials.getEmail());
//        }
//        return userVerificationCodeDto;
//    }
}
