import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { MovieapiService } from '../apiService/movieapi.service';
import { TicketData } from '../model/ticket-data';
import { AuthapiService } from '../apiService/authapi.service';
import { MovieData } from '../model/movie-data';

@Component({
  selector: 'app-book-movie',
  templateUrl: './book-movie.component.html',
  styleUrls: ['./book-movie.component.css']
})
export class BookMovieComponent {
  selectedMovie: MovieData | any;
  bookingSuccess: boolean | null = null;
  loading: boolean = false;
  movieName: string | any;
  theaterName: string | any;
  movieId: string | any;
  bookingForm: FormGroup;

  finalToken = this.authService.getUserToken();
  username: string | any;
  constructor(private fb: FormBuilder, private route: ActivatedRoute, private router: Router, private movieService: MovieapiService, private authService: AuthapiService) {
    this.bookingForm = this.fb.group({
      movieName: ['', Validators.required],
      theaterName: ['', Validators.required],
      numberOfTickets: [null, Validators.required],
    });
  }

  onSubmit(): void {
    this.username = this.authService.getUsername();
    const bookingData: TicketData = {
      seatNumbers: ['A1'],
      numberOfTickets: this.bookingForm.controls['numberOfTickets'].value,
      movieName: this.bookingForm.controls['movieName'].value,
      theaterName: this.bookingForm.controls['theaterName'].value,
      userName: this.username
    };

    if (this.bookingForm.invalid) {
      this.loading = false;
      return;
    }
    this.loading = true;
    this.movieService.bookMovie(this.finalToken, this.movieName, bookingData).subscribe(res => {
      console.log(res);
      this.bookingSuccess = true;
      this.loading = false;

      this.bookingForm.reset();

    }, err => {
      this.loading = false;
      console.log('this is error')
      if (err.error.text === 'Successfully booked movie test') {
        this.bookingSuccess = true;
      } else {
        this.bookingSuccess = false;

      }
      console.log(err);
      console.log(bookingData);
    });


  }


  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      this.movieName = params['movieName'];
      this.theaterName = params['theaterName'];
      this.movieId = params['movieId'];
      console.log(params);
      this.bookingForm.setValue({
        movieName: this.movieName,
        theaterName: this.theaterName,
        numberOfTickets: this.bookingForm.controls['numberOfTickets'].value
      });
    });

    this.movieService.getMovieById(this.finalToken, this.movieId).subscribe(data => {
      console.log('movie searching....byid');
      console.log(data);
      this.selectedMovie = data

    }, err => {
      console.log(err);
    })
  }
}
