#define TWILIO_SEND
#define TWILIO_API_SIZE (450 * sizeof(char))

static int
twilio_send(const char *msg, int async) {
	char *cmd = (char *)malloc(TWILIO_API_SIZE);
	int r = snprintf(cmd, TWILIO_API_SIZE,
		"curl -X POST https://api.twilio.com/2010-04-01/Accounts/{account}/SMS/Messages.json"
		" -u {username}:{password}"
		" --data-urlencode 'From=+{twilio-number}'"
		" --data-urlencode 'To=+{phone-number}'"
		" --data-urlencode 'Body=%s'"
		"%s", msg, async ? " &" : "");
	if (r == -1) return r;
	r = system(cmd);
	free(cmd);
	return r;
}
