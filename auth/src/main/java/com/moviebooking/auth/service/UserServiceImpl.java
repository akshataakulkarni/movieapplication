package com.moviebooking.auth.service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.moviebooking.auth.exception.InvalidInputException;
import com.moviebooking.auth.model.ERole;
import com.moviebooking.auth.model.Role;
import com.moviebooking.auth.model.User;
import com.moviebooking.auth.payload.LoginRequest;
import com.moviebooking.auth.payload.ResetRequest;
import com.moviebooking.auth.payload.SignupRequest;
import com.moviebooking.auth.repository.RoleRepository;
import com.moviebooking.auth.repository.UserRepository;

@Service
public class UserServiceImpl implements UserService {
	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;
	Map<String , String> obj= new HashMap<String, String>();
	@Override
	public ResponseEntity<?> addUser(SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return new ResponseEntity<>("Username is already exists!" , HttpStatus.BAD_REQUEST);
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
	
			return new ResponseEntity<>("Email is already exists!", HttpStatus.BAD_REQUEST);
		}

		User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(), signUpRequest.getPassword(),
				signUpRequest.getSecurityQuestion(), signUpRequest.getSecurityAnswer());

		Set<String> strRoles = signUpRequest.getRoles();

		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName("ROLE_CUSTOMER")
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByName("ROLE_ADMIN")
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);
					break;
				default:
					Role userRole = roleRepository.findByName("ROLE_CUSTOMER")
							.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);
		obj.put("msg", "User registered successfully");
		return new ResponseEntity<>(obj, HttpStatus.OK);
	}

	@Override
	public boolean loginUser(LoginRequest loginRequest) {
		Optional<User> userObj = userRepository.findByUsername(loginRequest.getUsername());
		if (userObj.isPresent() && userObj.get().getPassword().equals(loginRequest.getPassword())) {
			return true;
		}
		return false;
	}

	@Override
	public ResponseEntity<?> updatePassword(ResetRequest resetRequest) {

		if (!userRepository.existsByUsername(resetRequest.getUsername())) {
			return new ResponseEntity<>("Username doesn't exists!", HttpStatus.BAD_REQUEST);
		}
		Optional<User> userdata = userRepository.findByUsername(resetRequest.getUsername());
		if (resetRequest.getSecQuestion().equals(userdata.get().getSecurityQuestion())
				&& resetRequest.getSecAnswer().equals(userdata.get().getSecurityAnswer())) {
			userdata.get().setPassword(resetRequest.getNewPassword());
			userRepository.save(userdata.get());
			return new ResponseEntity<>("changed password successfully!", HttpStatus.ACCEPTED);
		}
		return new ResponseEntity<>("could not update password(cause:sec ques not match)!", HttpStatus.BAD_REQUEST);

	}

	@Override
	public List<User> getAllUsers() {

		return null;
	}

	@Override
	public Optional<User> getUserByUsername(String username) {

		Optional<User> user = userRepository.findByUsername(username);
		if (user.isEmpty()) {
			throw new InvalidInputException("username is not present");
		}
		return user;
	}

}
