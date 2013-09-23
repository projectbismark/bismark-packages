#!/bin/ash
#simple_webtest.sh
#Ben Jones
#Sep 2013
#simple_webtest.sh: this script is designed to run on the bismark platform. The script will fetch a number of urls and determine the
# the performance of these webpages. The performance data will allow us to see performance difference inside and outside of countries

#configuration parameters
user_agent='Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)'
#num_redirects=5 the initial version will not be using redirects so that we just get the first http page and don't have to do HTTPS validation
output_format="actual_url:\\t%{url_effective};speed:\\t%{speed_download};code:\\t%{http_code}\\n\
lookup_time:\\t%{time_namelookup};connect_time:\\t%{time_connect};total_time:\\t%{time_total};\\n\
size:\\t%{size_download};"
persistentdir="/tmp/censorship-performance-measurements"
url_dload_address=ben.noise.gatech.edu/external/censorship-performance/simple-http
min_wait=1 #the minimum time to wait between web tests
max_wait=2 #the maximum time to wait between web tests
max_experiment_time=120 #experiment must be done in 120 seconds
url_timeout=60 #after 60 seconds, timeout the url
max_curl_filesize=$((500 * 1024)) # 400k
iteration_dload_cap=`expr 10 \* 1024` #10k

#FUNCTIONS
#setup: this function will prepare the environment for the test
# expected syntax: setup
setup()
{
    echo "Setting up"
    timestamp=`date +%s`
    test_start_time=$timestamp
    
    . /etc/bismark/bismark.conf
    . /usr/lib/bismark/functions.inc.sh

    #find the device ID, aka the mac address (since this is used in filenames, we replace the : with a -
    DEVICE_ID=`cat /etc/bismark/ID`

    #and persistent files (eventually deleted after uploads)
    output_dir_name=http_${DEVICE_ID}_${timestamp}
    output_dir=${persistentdir}/${output_dir_name}
    mkdir -p $output_dir; cd $output_dir || exit 1
    output_file_rel_name=http_results_${DEVICE_ID}_${timestamp}.txt
    output_file=${output_dir}/${output_file_rel_name}
    upload_dir=/tmp/bismark-uploads/censorship-performance/
    input_file=${persistentdir}/cur_url_list

    compressed_data_file=${output_dir}/${output_dir_name}.tar #this is the archive which we will be storing output in

    #create a file for the variable index if it does not exist
    index_file=${persistentdir}/index.var
    if [ ! -e $index_file ]; then
	touch $index_file
    fi
    
    #if commands are different on busybox, then use a variable for their version
    mktemp='/bin/busybox mktemp'
    cat='/bin/busybox cat'
}

#dload_url_list: sets url_file and download_url, then writes the new urls to url_file
dload_url_list()
{
    #and download the file of urls
    url_file=${persistentdir}/urllist.txt
    download_url=${url_dload_address}/${DEVICE_ID}.txt
    echo $download_url
    curl $download_url > $url_file
    
}


#cleanup: this function will delete all temporary files and do cleanup before the script exits
cleanup()
{
    echo "Cleaning up"
    #delete the content
    cd $persistentdir
    rm -rf $output_dir
}

#pick_elem: this function will randomly select n elements from a list. If all elements are selected, the list order will be randomized
# The expected syntax is echo list | pick_elem $n and the list is piped to the function
#Note: this function is copied from Giuseppe's measurement script because it seems to be an efficient way to randomize lists
pick_elem()
{
    if [ $# -eq '1' ]; then
	n=$1
    else n="NR" #if the list length is not given, then use the number of lines read in as the length
    fi

    #seed the random number generator
    rnd_seed=$(($timestamp + `cut -d" " -f1 /proc/self/stat` ))

    #use awk to read the list in, then sort it or return a random element
    awk 'BEGIN {srand('$rnd_seed')}
               {l[NR]=$0;}
         END   {if (FNR==0){exit};
                 for (i=1;(i<='$n' && i<=NR);i++){
                     n=int(rand()*(NR-i+1))+i;
                     print l[n];l[n]=l[i];
                 }
               }'
}

#create_random_url_list: take the url list, put it in random order, and write it out as a new file
#Note: will overwrite input_file if it exists
create_random_url_list()
{
    if [ -e "$input_file" ]; then #if the old file exists, delete it
	rm -f $input_file
    fi
	
    #note, dload_url_list should have been called by now so that there is a url file to read
    if [ ! -e "$url_file" ]; then #if the url file does not exist, then print an error message and exit
	echo "No URL file detected. Exiting"
	#perform any cleanup necessary
	cleanup
	exit 1
    fi
	
    echo "Randomizing the url order"
    #create a file to hold the url list
    cd $persistentdir
    #randomize the url list and write it out
    $cat $url_file | pick_elem > $input_file
}

#pick_random_urls: will select the $index through $index + $urls_to_test urls and print them to stdout
#Sets: index
pick_random_url()
{
    cur_loc=0
    endoflist=`expr $index + 1`

    while read line; do
	if [ "$cur_loc" -ge "$endoflist" ]; then
	    break
	fi
	if [ "$cur_loc" -ge "$index" ]; then
	    echo $line
	fi
	cur_loc=`expr $cur_loc + 1`
    done < $input_file
}

#upload_data: upload the data to the BISmark servers
upload_data()
{
    #move to the output directory and gzip the tar archive
    cd $persistentdir
    tar -zcf ${output_dir_name}.tar.gz ${output_dir_name}
    mv ${output_dir_name}.tar.gz $upload_dir
}

#measure_site: this function will perform the actual measurements.
# expected syntax: measure_site url
measure_site()
{
    #create a filename to store the html and headers in- just the name of the website
    pageoutput=${output_dir}/${1}
    printf "site:\t%s;time:\t%s\n" "$1" `date +%s`>> $output_file
    curl $1 --max-filesize $max_curl_filesize -A "$user_agent" -w $output_format -o ${pageoutput}.html -D ${pageoutput}.headers --max-time $url_timeout >> $output_file
    printf "return_code:\t%s\n" "$?" >> $output_file
}

#syntax: compress_data $url, will take the header and 
compress_data()
{
    cd $persistentdir
    tar -zcf ${output_dir_name}.tar.gz ${output_dir_name}
    cd $output_dir
}

#run_measurements: will run the measurements for this test.
# syntax: run_measurements
#Sets: index, url, 
run_measurements()
{
    echo "Measuring"
    #we store the variable index to disc so we have persistent data between reboots-> the file just stores the file
    . $index_file

    #randomize the order of the urls if we haven't already
    #we test whether or not to create the new url list by checking if the index exists or if it is >=100
    
    if [ "$index" = "" ] || [ $index -ge 99 ]
    then
	#set index to 0 and create the randomized url list
	index=0
	dload_url_list
	create_random_url_list
    fi

    #acquire the measurements lock so we are the only script running
    if acquire_active_measurements_lock simple_webtest; then
        #here we get a url, tar the output, check the upload size, and if the size is larger than our cap, we end the script
	local data_usage=0
	while [ $data_usage -lt $iteration_dload_cap ] && [ $index -le 100 ]; do
	    local url=`pick_random_url`
	    index=`expr $index + 1` #this must be set here so that we get the next url when we run through again
	    echo $url
	    measure_site $url
	    compress_data $url
	    
            #update our data usage numbers
	    data_usage=`ls -l ../${output_dir_name}.tar.gz | awk '{print $5}'`
	    echo "Current data usage: " $data_usage " (Per iteration cap is " $iteration_dload_cap ")"

	    #if we are over time, then break
	    local time_elapsed=$((`date +%s` - test_start_time))
	    if [ $time_elapsed -gt $max_experiment_time ]; then
		echo "Overtime. Stopping test"
		echo "Could not test other urls- experiment is out of time" >>  $output_file
		break #break out of the loop and cleanup
	    fi
	done
	release_active_measurments_lock

	#write out our changes so that we keep our state on the next run
	echo index="$index" > $index_file
	upload_data

    else
	#if we don't acquire, then just quit
	expire_active_measurements_lock
    fi

}

#MAIN- START- here is where the code is actually run
main()
{
    setup
    run_measurements
    cleanup
}

main