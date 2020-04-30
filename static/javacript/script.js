/*javascript method to call background process*/
('#idform').on('submit', function () {
	$.getJSON('/background_process', {
	    domain: $('input[name="domain"]').val(),
		}, function(data) {
		$("#result").text(data.result);
		});
		return false;
		});
