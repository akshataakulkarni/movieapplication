package com.cognizant.moviebookingapp.model;

import java.util.Set;

import org.springframework.data.mongodb.core.mapping.Document;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Transient;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Entity
public class Ticket {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long transactionId;

	@NotNull
	@Min(value = 0, message = "numberOfTickets must be at least 1")
	@Max(value = 100, message = "numberOfTickets must be at most 100")
	private int numberOfTickets;

	
	private Set<String> seatNumbers;

	@NotBlank
	private String movieName;

	@NotBlank
	private String theaterName;

	@NotBlank
	private String userName;

	public Ticket() {
	}

	public Ticket(Long transactionId, @NotNull @Min(1) int numberOfTickets, @NotNull Set<String> seatNumbers,
			@NotBlank String movieName, @NotBlank String theaterName, @NotBlank @NotBlank @NotBlank String userName) {
		this.transactionId = transactionId;
		this.numberOfTickets = numberOfTickets;
		this.seatNumbers = seatNumbers;
		this.movieName = movieName;
		this.theaterName = theaterName; 
		this.userName = userName;
	}

	public Long getTransactionId() {
		return transactionId;
	}

	public void setTransactionId(Long transactionId) {
		this.transactionId = transactionId;
	}

	public int getNumberOfTickets() {
		return numberOfTickets;
	}

	public void setNumberOfTickets(int numberOfTickets) {
		this.numberOfTickets = numberOfTickets;
	}

	public Set<String> getSeatNumbers() {
		return seatNumbers;
	}

	public void setSeatNumbers(Set<String> seatNumbers) {
		this.seatNumbers = seatNumbers;
	}

	public String getMovieName() {
		return movieName;
	}

	public void setMovieName(String movieName) {
		this.movieName = movieName;
	}

	public String getTheaterName() {
		return theaterName;
	}

	public void setTheaterName(String theaterName) {
		this.theaterName = theaterName;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

}
