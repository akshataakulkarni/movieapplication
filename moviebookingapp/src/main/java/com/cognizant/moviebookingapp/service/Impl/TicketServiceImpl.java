package com.cognizant.moviebookingapp.service.Impl;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.cognizant.moviebookingapp.model.Movie;
import com.cognizant.moviebookingapp.model.Ticket;
import com.cognizant.moviebookingapp.repository.MovieRepository;
import com.cognizant.moviebookingapp.repository.TicketRepository;
import com.cognizant.moviebookingapp.service.TicketService;


@Service
public class TicketServiceImpl implements TicketService {

	@Autowired
	TicketRepository ticketRepo;

	@Autowired
	MovieRepository movieRepo;

	Map<String , String> obj= new HashMap<String, String>();
	@Override
	public ResponseEntity<?> bookMovie(String movieName, Ticket ticket) {
		Optional<Movie> movie = movieRepo.findByMovieName(movieName);
		if (movie.isEmpty()) {
			obj.put("msg", "Movie not found");
			return new ResponseEntity<>(obj, HttpStatus.NOT_FOUND);
		}

		int availableTickets = movie.get().getTotalTickets();
		int totalTicketsBuy = ticket.getNumberOfTickets();
		if (availableTickets <= 0) {
			return new ResponseEntity<>("All tickets sold out", HttpStatus.BAD_REQUEST);
		}
		if (availableTickets < totalTicketsBuy) {
			return new ResponseEntity<>("Insufficient tickets available", HttpStatus.BAD_REQUEST);
		}

//		Set<String> bookedSeatsMovie = movie.get().getBookedSeats();
//		Set<String> seatNumbersTicket = ticket.getSeatNumbers();

//		if (totalTicketsBuy != seatNumbersTicket.size()) {
//			return new ResponseEntity<>("Number of tickets does not match number of seat numbers",
//					HttpStatus.BAD_REQUEST);
//		}
//
//		Set<String> invalidSeatNumbers = validateSeatNumbers(ticket.getSeatNumbers());
//		if (!invalidSeatNumbers.isEmpty()) {
//			return new ResponseEntity<>("Invalid seat numbers: " + invalidSeatNumbers, HttpStatus.BAD_REQUEST);
//		}

//		Set<String> duplicates = findDuplicates(bookedSeatsMovie, seatNumbersTicket);
//		if (!duplicates.isEmpty()) {
//			return new ResponseEntity<>("Seats are already booked: " + duplicates, HttpStatus.CONFLICT);
//		}

		int finalTicketCount = availableTickets - totalTicketsBuy;
		Ticket newTicket = new Ticket();
		newTicket.setNumberOfTickets(ticket.getNumberOfTickets());
		newTicket.setSeatNumbers(ticket.getSeatNumbers());
		newTicket.setMovieName(movieName);
		newTicket.setTheaterName(movie.get().getTheaterName());
		newTicket.setUserName(ticket.getUserName());
//		bookedSeatsMovie.addAll(seatNumbersTicket);
		movie.get().getTickets().add(newTicket);
		movie.get().setTotalTickets(finalTicketCount);
		ticketRepo.save(newTicket);
		obj.put("msg", "Successfully booked movie "+ movieName);
		return new ResponseEntity<>( obj, HttpStatus.CREATED);
	}

	@Override
	public ResponseEntity<?> getAllTickets() {
		try {
			List<Ticket> tickets = ticketRepo.findAll();
//			obj.put("msg", "tickets");
			return new ResponseEntity<>(tickets, HttpStatus.OK);
		} catch (Exception e) {
			obj.put("msg", "Error occurred while fetching tickets: " + e.getMessage());
			return new ResponseEntity<>(obj ,HttpStatus.INTERNAL_SERVER_ERROR);
		}
	}

	@Override
	public ResponseEntity<?> getTicketsUser(String userId) {
		List<Ticket> userTickets = ticketRepo.findByUserName(userId);
//		obj.put("msg", "userTickets");
		return new ResponseEntity<>(userTickets, HttpStatus.OK);
	}

	public static String generateTransactionId() {
		final String PREFIX = "TXN-";
		final int RANDOM_BOUND = 100;
		Random random = new Random();
		int randomNumber = random.nextInt(RANDOM_BOUND);
		LocalDateTime now = LocalDateTime.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmssSSS");
		String timestamp = now.format(formatter);
		String transactionId = PREFIX + timestamp + randomNumber;
		return transactionId;
	}

	private Set<String> findDuplicates(Set<String> set1, Set<String> set2) {
		Set<String> duplicates = new HashSet<>();
		for (String s : set1) {
			if (set2.contains(s)) {
				duplicates.add(s);
			}
		}
		return duplicates;
	}

	private Set<String> validateSeatNumbers(Set<String> seatNumbersTicket) {
		Set<String> invalidSeatNumbers = new HashSet<>();
		for (String seatNumber : seatNumbersTicket) {
			if (!seatNumber.matches("^[A-J]\\d{1,2}$")) {
				invalidSeatNumbers.add(seatNumber);
			} else {
				int row = seatNumber.charAt(0) - 'A' + 1;
				int col = Integer.parseInt(seatNumber.substring(1));
				if (row < 1 || row > 10 || col < 1 || col > 10) {
					invalidSeatNumbers.add(seatNumber);
				}
			}
		}
		return invalidSeatNumbers;
	}

}
