package manuel.demojwt.auth;

import lombok.RequiredArgsConstructor;
import manuel.demojwt.jwt.JwtService;
import manuel.demojwt.user.CustomUserDetail;
import manuel.demojwt.user.Role;
import manuel.demojwt.user.User;
import manuel.demojwt.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        UserDetails userDetails = new CustomUserDetail(user);
        String token = jwtService.getToken(userDetails);
        return AuthResponse.builder()
                .token(token)
                .build();
    }

    public AuthResponse register(RegisterRequest request) {
        User user = User.builder()
                .username(request.username)
                .password(passwordEncoder.encode(request.password))
                .firstname(request.firstname)
                .lastname(request.lastname)
                .country(request.country)
                .role(Role.USER)
                .build();

        userRepository.save(user);

        CustomUserDetail customUserDetail = new CustomUserDetail(user);

        return AuthResponse.builder()
                .token(jwtService.getToken(customUserDetail))
                .build();
    }
}
