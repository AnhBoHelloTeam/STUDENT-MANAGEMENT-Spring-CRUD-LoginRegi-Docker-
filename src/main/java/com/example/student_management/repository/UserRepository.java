package com.example.student_management.repository;

import com.example.student_management.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);  // ✅ Thêm phương thức tìm kiếm bằng email
}
