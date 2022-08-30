package com.example.security1.repository;

import com.example.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository 가 들고있다.
// @Repository 라는 어노테이션이 없어도 IoC가 된다. 이유는 JpaRepository 를 상속했기 때문에 자동 빈 등록
public interface UserRepository extends JpaRepository<User, Integer> {

    // findBy 규칙 -> Username 문법
    // select * from user where username = ?
    User findByUsername(String username);


}
