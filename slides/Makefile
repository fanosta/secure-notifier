MAINDOCUMENTBASENAME = presentation
MAINDOCUMENTFILENAME = ${MAINDOCUMENTBASENAME}.tex

PDFLATEX_CMD = pdflatex
#BIBTEX_CMD = bibtex
BIBTEX_CMD = biber

.PHONY: all
all: pdf

.PHONY: pdf
pdf:
	${PDFLATEX_CMD} ${MAINDOCUMENTFILENAME}
	-${BIBTEX_CMD} ${MAINDOCUMENTBASENAME}
	${PDFLATEX_CMD} ${MAINDOCUMENTFILENAME}
	${PDFLATEX_CMD} ${MAINDOCUMENTFILENAME}

.PHONY: clean
clean:
	-rm -r *.aux *.blg *.log *.nav *.out *.snm *.toc *.bbl *.bcf *.run.xml *.vrb -f

run:
	pdfpc -n right $(MAINDOCUMENTBASENAME).pdf

#help	purge	cleaner than clean ;-)
.PHONY: purge run
purge: clean
	-rm ${MAINDOCUMENTBASENAME}.pdf
