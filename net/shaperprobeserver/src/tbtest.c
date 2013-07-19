#include <stdio.h>

int getLevelShift(double *timestamp, double *rate, int *rank, 
		int *index, double t, double rateEstimate,
		unsigned int *minbktdepth, unsigned int *maxbktdepth,
		double *tbrate);

int main(int argc, char **argv)
{
	FILE *fp = fopen(argv[0], "r");
	if(fp == NULL) return 0;

	double timestamps[2000]; // = {1242185775.055574,1242185775.506130,1242185775.959595,1242185776.405912,1242185776.859393,1242185777.305232,1242185777.755197,1242185778.205728,1242185778.659453,1242185779.105410,1242185779.555487,1242185780.009747,1242185780.463209,1242185780.916819,1242185781.355853,1242185781.809494,1242185782.260493,1242185782.714048,1242185783.155697,1242185783.609337};
	double rateEstimates[2000]; // = {8213.333333,8312.888889,8213.333333,7964.444444,8337.777778,8039.111111,8288.000000,8064.000000,8462.222222,8462.222222,8263.111111,8213.333333,1070.222222,1070.222222,1045.333333,1070.222222,1070.222222,1070.222222,1045.333333,1045.333333};
	double ratetstamps[2000];
	double timestamp[2000] = {0};
	double rate[2000] = {0};
	int rank[2000] = {0};
	double tbrate;
	unsigned int minbktdepth, maxbktdepth;
	int index = -1;
	int i = 0, n = 0;

	char line[2000];
	while(!feof(fp))
	{
		memset(line, '\0', 2000);
		fgets(line, 2000, fp);
		char *token;
		token = strtok(line, " ");
		token = strtok(NULL, " ");
		timestamps[n] = atof(token);
		n++;
	}

	double bucket = 0.5;
	double oldbucket = -1, oldtstamp = 0;
	int tn = 0, raten = 0;;
	for(i = 0; i < n; i++)
	{
		float curbucket = floor((timestamps[i]-timestamps[0])/bucket);
		if(oldbucket == -1) oldbucket = curbucket;
		if(curbucket != oldbucket)
		{
			ratetstamps[raten] = timestamps[i];
			rateEstimates[raten++] = tn*1400*0.008/(timestamps[i]-oldtstamp);
			oldtstamp = timestamps[i];
			tn = 1;
		}
		oldbucket = curbucket;
		tn++;
	}

	for(i = 0; i < raten; i++)
	{
		if(getLevelShift(timestamp, rate, rank, &index, ratetstamps[i],
				rateEstimates[i], &minbktdepth, &maxbktdepth,
				&tbrate) == 1)
		{
			printf("found: bucket: [%d %d], rate %f", 
					minbktdepth, maxbktdepth, tbrate);
			break;
		}
	}

	fclose(fp);

	return 0;
}

