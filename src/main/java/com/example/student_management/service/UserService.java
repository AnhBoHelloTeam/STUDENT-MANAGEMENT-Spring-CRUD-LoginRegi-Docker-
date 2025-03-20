package com.example.student_management.service;

import com.example.student_management.entity.User;
import com.example.student_management.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;
import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private static final List<String> VALID_ROLES = List.of("USER", "ADMIN");

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User registerUser(String username, String email, String password, Set<String> roles) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new RuntimeException("Username already exists!");
        }
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Email already exists!");
        }

        // ✅ Nếu không có role -> Mặc định là USER
        if (roles == null || roles.isEmpty()) {
            roles = Set.of("USER");
        }

        // ✅ Kiểm tra role hợp lệ
        Set<String> validatedRoles = new HashSet<>();
        for (String role : roles) {
            if (VALID_ROLES.contains(role.toUpperCase())) {
                validatedRoles.add(role.toUpperCase());
            }
        }

        // ✅ Nếu không có role hợp lệ nào -> Mặc định là USER
        if (validatedRoles.isEmpty()) {
            validatedRoles.add("USER");
        }

        User user = new User(username, email, passwordEncoder.encode(password), validatedRoles);
        return userRepository.save(user);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
