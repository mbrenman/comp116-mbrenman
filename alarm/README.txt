Comp 116 Homework 2
Matt Brenman
Due: 10/08/2013 11:59 PM

Almost everything is working up to spec, except I seem to be getting
a very high amount of false positives for credit card numbers. This
is because the cookies or tokens that are sometimes passed between
sites contain strings of numbers, and the regex for a potential
credit card number is very general.

I also used the PacketFu docs, the Piazza postings, and the recommended
readings for assistance. Also, I utilized stackoverflow for questions 
about Ruby syntax and structure.
