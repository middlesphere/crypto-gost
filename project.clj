(defproject crypto-gost "0.1"
  :description "Clojure Bouncycastle wrapper to work with GOST"
  :url "https://github.com/middlesphere/crypto-gost"
  :author "Mikhail Ananev"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  
  :dependencies [[org.clojure/clojure "1.8.0"]]
  :profiles {:dev      {:dependencies [[org.bouncycastle/bcprov-jdk15on "1.57"]]}
             :provided {:dependencies [[org.bouncycastle/bcprov-jdk15on "1.57"]]}})
