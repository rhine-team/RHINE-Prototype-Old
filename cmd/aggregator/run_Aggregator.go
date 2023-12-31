package main

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"path/filepath"

	"github.com/google/certificate-transparency-go/x509"
	pf "github.com/rhine-team/RHINE-Prototype/internal/components/aggregator"
	"github.com/rhine-team/RHINE-Prototype/internal/components/aggregator/aggserver"

	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"
	"github.com/spf13/cobra"

	"google.golang.org/grpc"
)

var configPath string
var testParentZone string
var testCertPath string
var parentCertDirectoryPath string
var Finput int
var consoleOff bool
var timeout = time.Second * 7200

var rootCmd = &cobra.Command{
	Use:   "run_Aggregator",
	Short: "Aggregator server",
	Long:  "Server running an aggregator needed for RHINE",
	Run: func(cmd *cobra.Command, args []string) {
		if consoleOff {
			rhine.DisableConsoleOutput()
		}

		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}

		// Make a new Agg struct
		aggr := rhine.NewAggManager(cof)

		aggr.F = Finput

		// Run the Agg
		lis, err := net.Listen("tcp", cof.ServerAddress)
		if err != nil {
			log.Fatalf("Listen failed: %v", err)
		}

		s := grpc.NewServer(
			grpc.MaxMsgSize(rhine.MaxMsg),
			grpc.MaxRecvMsgSize(rhine.MaxMsg),
			grpc.MaxSendMsgSize(rhine.MaxMsg),
		)
		pf.RegisterAggServiceServer(s, &aggserver.AggServer{AggManager: aggr})

		log.Println("Rhine Aggregator server online at: ", cof.ServerAddress)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Serving failed: %v", err)
		}
	},
}

var WipeDB = &cobra.Command{
	Example: "./run_Aggregator WipeDB",
	Use:     "WipeDB",
	Short:   "Wiped the Aggregator DB",
	Long:    "Deletes everything from the badger DB of the Aggregator",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}
		log.Println("Configuration file parsed.")

		// Make a new Log struct
		aggr := rhine.NewAggManager(cof)

		log.Println("New Aggregator Manager initialized")

		err := aggr.DB.DropAll()
		if err != nil {
			log.Println("Deletions failed!")
		} else {
			log.Println("All badger data has been dropped with succes!")
		}
	},
}

var StartLogres = &cobra.Command{
	Example: "./run_Aggregator StartLogres",
	Use:     "StartLogres",
	Short:   "Logres",
	Long:    "Logres",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}
		log.Println("Configuration file parsed.")

		// Make a new Log struct
		AggManager := rhine.NewAggManager(cof)

		log.Println("New Aggregator Manager initialized")

		clientsLogger := make([]pf.AggServiceClient, len(AggManager.AggList))
		// Make connections for all designated loggers

		logresreq := &pf.StartLogresRequest{}
		var wg sync.WaitGroup
		wg.Add(1) //len(clientsLogger)

		for i, logger := range AggManager.AggList {
			log.Println("Agglist")
			i := i
			logger := logger

			if i > 0 {
				break
			}

			// Create connections and clients, remember to reuse later
			conn := rhine.GetGRPCConn(logger)
			defer conn.Close()
			clientsLogger[i] = pf.NewAggServiceClient(conn)

			go func() {
				defer wg.Done()
				log.Println("In the go send routine")
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()

				r, err := clientsLogger[i].StartLogres(ctx, logresreq)
				if err != nil {
					log.Printf("No good response: %v", err)
				} else {
					log.Println("Got response: ", r)
				}

			}()

		}
		wg.Wait()
	},
}

var AddTestDT = &cobra.Command{
	Example: "./run_Aggregator AddTestDT",
	Use:     "AddTestDT --parent=ethz.ch --certPath=data/cert.pem",
	Short:   "Construct DT data structure to conduct a test run for some zone",
	Long:    "Construct DT data structure to conduct a test run for some zone",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}
		log.Println("Configuration file parsed.")

		// Make a new Log struct
		aggr := rhine.NewAggManager(cof)

		log.Println("New Aggregator Manager initialized")

		aL := rhine.AuthorityLevel(0b0001)

		//Load cert
		var cert *x509.Certificate
		if testCertPath != "" {
			var err error
			cert, err = rhine.LoadCertificatePEM(testCertPath)
			if err != nil {
				log.Fatal("Error loading certificate: ", err)
			}
		} else {
			log.Fatal("Must provide a parent cert!")
		}
		pCert := rhine.ExtractTbsRCAndHash(cert, false)
		expirationTime := time.Now().Add(time.Hour * 24 * 180)

		aggr.Dsalog.AddDelegationStatus(testParentZone, aL, pCert, expirationTime, "testzonechild."+testParentZone, rhine.AuthorityLevel(0b0001), []byte{}, aggr.DB)
		log.Println("Added test DSA to Aggregator database")

		/*
			// Test if workes
			dsp, errdsp := aggr.Dsalog.DSProofRet(testParentZone, "testzonechild."+testParentZone, rhine.ProofOfPresence, aggr.DB)
			if errdsp != nil {
				log.Fatalln("Something went wrong! ", errdsp)
			}
			log.Printf("Looks like %+v", dsp)
			boolres, errres := dsp.Proof.VerifyMPathProof(dsp.Dsum.Dacc.Roothash, "testzonechild."+testParentZone)
			log.Println("Res ", boolres, errres)
		*/
	},
}

var AddDTBatch = &cobra.Command{
	Example: "./run_Aggregator AddDTBatch",
	Use:     "AddDTBatch --config=data/configs/AggConfig.json --pCertDir=data/temp/parentcerts",
	Short:   "Construct DT data structure in bulk",
	Long:    "Construct DT data structure in bulk",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}
		log.Println("Configuration file parsed.")

		// Make a new Agg struct
		aggr := rhine.NewAggManager(cof)

		log.Println("New Aggregator Manager initialized")

		aL := rhine.AuthorityLevel(0b0001)

		// Iterate over all cert files in the dir
		filepath.Walk(parentCertDirectoryPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Fatalf("The following error while iterating: ", err.Error())
			}
			// Check if the correct prefix is present
			if strings.HasPrefix(info.Name(), "CERT_") {
				//Load cert
				cert, err := rhine.LoadCertificatePEM(path)
				if err != nil {
					log.Fatal("Error loading certificate: ", err)
				}
				// Add to DB
				pCert := rhine.ExtractTbsRCAndHash(cert, false)
				expirationTime := time.Now().Add(time.Hour * 24 * 180)

				pZoneName := strings.TrimPrefix(info.Name(), "CERT_")
				pZoneName = strings.Replace(pZoneName, ".pem", "", 1)
				aggr.Dsalog.AddDelegationStatus(pZoneName, aL, pCert, expirationTime, "testzonechild."+testParentZone, rhine.AuthorityLevel(0b0001), []byte{}, aggr.DB)

			}
			return nil
		})
	},
}

func init() {
	rootCmd.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	rootCmd.Flags().BoolVar(&consoleOff, "nostd", false, "Disables standard output")
	rootCmd.Flags().IntVar(&Finput, "f", 2, "Logres f")
	WipeDB.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	AddTestDT.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	AddTestDT.Flags().StringVar(&testParentZone, "parent", "ethz.ch", "ParentZone")
	AddTestDT.Flags().StringVar(&testCertPath, "certPath", "example.pem", "CertificatePath")
	AddDTBatch.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	AddDTBatch.Flags().StringVar(&parentCertDirectoryPath, "pCertDir", "data/temp/parentcerts/", "PathToParentCertDir")
	StartLogres.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
}

func main() {
	rootCmd.AddCommand(WipeDB)
	rootCmd.AddCommand(AddTestDT)
	rootCmd.AddCommand(AddDTBatch)
	rootCmd.AddCommand(StartLogres)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

}
