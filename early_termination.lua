-- Early Termination v1.0
-- Writen by Thomas Kager
-- tkager@linux.com

-- Created 3/24/2016
-- Last modified 3/25/16

--[[

- Purpose
The purpose of this script is to pull HTTP transaction security and performance data from a packet trace and analyze for command control based upon the
examination of early connection termination.

- Usage
tshark -r "(filename)" -2 -X lua_script:early_termination.lua -q

- Requirements
Requires Wireshark/Tshark 1.10 or later with LUA compiled. This can be determined through the "About Wireshark" menu option.
--]]


tap=Listener.new()

frame_number=Field.new("frame.number")
frame_time_relative=Field.new("frame.time_relative")
ip_src=Field.new("ip.src")
ip_dst=Field.new("ip.dst")
tcp_stream=Field.new("tcp.stream")
tcp_len=Field.new("tcp.len")
tcp_flags_reset=Field.new("tcp.flags.reset")
http_request_method=Field.new("http.request.method")
http_host=Field.new("http.host")
http_request_uri=Field.new("http.request.uri")
http_response_code=Field.new("http.response.code")
http_request_in=Field.new("http.request_in")
http_data=Field.new("http")
http_content_length=Field.new("http.content_length")
http_time=Field.new("http.time")

http = {}
track = {}


function tap.draw()

print()
print("---   HTTP Early Termination?")
		print()

		print(string.format("%-8s  %-15s  %-15s  %-20s  %-4s  %-20s  %-8s  %-8s  %-5s  %-8s  %-8s  %-7s  %-8s  %-8s", "Frame", "Client", "Server", "Host (last 20 bytes)", "Meth", "URI (first 20 bytes)", "C ConLen", "C ActLen", "Resp", "S ConLen", "S ActLen", "ReqTime", "RespTime", "RstTime"))
		print(string.format("%-8s  %-15s  %-15s  %-20s  %-4s  %-20s  %-8s  %-8s  %-5s  %-8s  %-8s  %-7s  %-8s  %-8s", "--------", "---------------", "---------------", "--------------------", "----", "--------------------", "--------", "--------", "-----", "--------", "--------", "-------", "--------", "--------"))


	correctorder = {} -- Create array for sorting. table.sort works on key values, not indexes
	for n in pairs(http) do
		table.insert(correctorder, string.format("%12d", n)) -- add leading 0's or it will sort alphabetically, e.g 5 will be greater than 1000.
	end

	table.sort(correctorder)

	for k, v in pairs (correctorder) do
		i = string.gsub(tostring(v) , " ", "")
		print (string.format("%-8s  %-15s  %-15s  %20s  %-4s  %-20s  %8s  %8s  %-5s  %8s  %8s  %-7.3f  %-8.3f  %-8s", i, http[i]["client"], http[i]["server"], string.sub(http[i]["host"], -20), http[i]["method"], string.sub(http[i]["uri"], 1, 20), http[i]["client_http_content_length"], http[i]["request_bytes"], http[i]["response_code"], http[i]["server_http_content_length"], http[i]["response_bytes"], tonumber(http[i]["request_time"]), tonumber(http[i]["response_time"]), http[i]["client_reset"], http[i]["reset"]))
	end


end

function tap.packet()

	if tcp_stream() ~= nil then
		stream=tostring(tcp_stream())

		if http_request_method() ~= nil then

			l_frame_number =  tostring(frame_number())
			http[l_frame_number] = {}
			http[l_frame_number]["client"] = tostring(ip_src())
			http[l_frame_number]["server"] = tostring(ip_dst())
			http[l_frame_number]["uri"] = tostring(http_request_uri())
			http[l_frame_number]["method"] = tostring(http_request_method())
			http[l_frame_number]["host"] = tostring(http_host())

			data_clean = string.gsub(tostring(http_data()), ":", "")
			http_hdr_len = tonumber(string.find(data_clean, "0d0a0d0a") or string.find(data_clean, "0a0a0a0a"))
			http[l_frame_number]["request_bytes"] = tostring(tcp_len()) - (((http_hdr_len -1)) /2 + 4)
			http[l_frame_number]["response_bytes"] = ""
			if http_content_length() ~= nil then
				http[l_frame_number]["client_http_content_length"] = tostring(http_content_length())
			else
				http[l_frame_number]["client_http_content_length"] = ""
			end
			http[l_frame_number]["server_http_content_length"] = ""
			http[l_frame_number]["request_time"] = tostring(frame_time_relative())
			http[l_frame_number]["response_code"] = "none"
			http[l_frame_number]["response_time"] = 0
			http[l_frame_number]["client_reset"] = ""
			http[l_frame_number]["reset"] = ""
			track[stream]=l_frame_number

		elseif http_response_code() ~= nil then

			if http_request_in() ~= nil then
				l_http_request_in = tostring(http_request_in())
				data_clean = string.gsub(tostring(http_data()), ":", "")
				http_hdr_len = tonumber(string.find(data_clean, "0d0a0d0a") or string.find(data_clean, "0a0a0a0a"))
				http[l_http_request_in]["response_bytes"] = tostring(tcp_len()) - (((http_hdr_len -1) /2) + 4)
				http[l_http_request_in]["response_code"] = tostring(http_response_code())
				if http_content_length() ~= nil then
					http[l_http_request_in]["server_http_content_length"] = tostring(http_content_length())
				else
					http[l_http_request_in]["server_http_content_length"] = ""
				end
				http[l_http_request_in]["response_time"] = tostring(http_time())
			end

		else

		if track[stream] ~= nil then
			tracked_frame = track[stream]

			if tonumber(tostring(tcp_len())) > 0 then

				if tostring(ip_src()) == http[tracked_frame]["client"] then
					http[tracked_frame]["request_bytes"] = http[tracked_frame]["request_bytes"] + tostring(tcp_len())
				else
					http[tracked_frame]["response_bytes"] = http[tracked_frame]["response_bytes"] + tostring(tcp_len())
				end

			elseif tostring(tcp_flags_reset()) == "1" then
				tracked_frame = track[stream]

				if tostring(ip_src()) == http[tracked_frame]["client"] then

					if http[tracked_frame]["reset"] == "" then
						http[tracked_frame]["client_reset"] = string.format("%5.3f",tostring(frame_time_relative()))
					end

				end
			else

			end

		end


	end

end  -- end tap.packet

end
