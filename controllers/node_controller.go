/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"k8s.io/client-go/tools/record"
	"os"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NodeReconciler reconciles a Node object
type NodeReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=nodes/status,verbs=get;update;patch

func (r *NodeReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	labelKey := os.Getenv("LABEL_KEY")
	if labelKey == "" {
		return ctrl.Result{}, fmt.Errorf("LABEL_KEY environment variable is missing")
	}

	labelValue := os.Getenv("LABEL_VALUE")
	if labelValue == "" {
		return ctrl.Result{}, fmt.Errorf("LABEL_VALUE environment variable is missing")
	}

	taintKey := os.Getenv("TAINT_KEY")
	if labelValue == "" {
		return ctrl.Result{}, fmt.Errorf("TAINT_KEY environment variable is missing")
	}

	taintValue := os.Getenv("TAINT_VALUE")
	if labelValue == "" {
		return ctrl.Result{}, fmt.Errorf("TAINT_VALUE environment variable is missing")
	}
	ctx := context.Background()
	log := r.Log.WithValues("node", req.NamespacedName)

	taintToAdd := corev1.Taint{
		Key:    taintKey,
		Value:  taintValue,
		Effect: corev1.TaintEffectNoSchedule,
	}

	isTaintAlreadyExist := false
	node := &corev1.Node{}
	if err := r.Get(ctx, req.NamespacedName, node); err != nil {
		log.Error(err, "Unable to fetch Node")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if node.DeletionTimestamp == nil {
		if node.Labels[labelKey] == labelValue {
			for _, taint := range node.Spec.Taints {
				if taint == taintToAdd {
					isTaintAlreadyExist = true
				}
			}

			if !isTaintAlreadyExist {
				node.Spec.Taints = append(node.Spec.Taints, taintToAdd)
				err := r.Update(ctx, node)
				if err != nil {
					log.Error(err, "Unable to update Node")
					return ctrl.Result{}, err
				}
				log.V(1).Info("Node updated", "node", node)
				r.Recorder.Event(node, corev1.EventTypeNormal, "Updated", "New taint add to Node - "+taintKey)
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Recorder = mgr.GetEventRecorderFor("Raz-Controller")

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}).
		Complete(r)
}
