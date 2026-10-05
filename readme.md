\#AUTH LOG PARSER

\#AUTH LOG PARSER



i created a CLI (command line interface) that helps in parsing and analysing authentication logs. 



it takes standard log files such as (var/log/auth.log) and gives a structured table of information such as- what is the timestamp of login, username, ip, port etc. 



it extracts information related to timestamp, username etc. 
At the end it gives a summary of all the authentication logs such as all the parsed events, skipped lines, total login attempts, successful logins, failed logins, top targeted usernames and top originating source ip. 

It also provides a help message when (--help) is called. It is proficient in error handling as well, skipping malformed lines and not throwing an error when the command line argument is left empty. 









